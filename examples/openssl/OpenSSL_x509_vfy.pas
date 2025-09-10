(* This unit was generated from the source file x509_vfy.h2pas 
It should not be modified directly. All changes should be made to x509_vfy.h2pas
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


unit OpenSSL_x509_vfy;


interface

// Headers for OpenSSL 1.1.1
// x509_vfy.h


{$MINENUMSIZE 4}
{$MINENUMSIZE 4}

uses
  OpenSSLAPI,
  OpenSSL_ssl,
  OpenSSL_ossl_typ;

const
  X509_L_FILE_LOAD = 1;
  X509_L_ADD_DIR   = 2;

  X509_V_OK                                       = 0;
  X509_V_ERR_UNSPECIFIED                          = 1;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            = 2;
  X509_V_ERR_UNABLE_TO_GET_CRL                    = 3;
  X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     = 4;
  X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      = 5;
  X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   = 6;
  X509_V_ERR_CERT_SIGNATURE_FAILURE               = 7;
  X509_V_ERR_CRL_SIGNATURE_FAILURE                = 8;
  X509_V_ERR_CERT_NOT_YET_VALID                   = 9;
  X509_V_ERR_CERT_HAS_EXPIRED                     = 10;
  X509_V_ERR_CRL_NOT_YET_VALID                    = 11;
  X509_V_ERR_CRL_HAS_EXPIRED                      = 12;
  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       = 13;
  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        = 14;
  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       = 15;
  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       = 16;
  X509_V_ERR_OUT_OF_MEM                           = 17;
  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          = 18;
  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            = 19;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    = 20;
  X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      = 21;
  X509_V_ERR_CERT_CHAIN_TOO_LONG                  = 22;
  X509_V_ERR_CERT_REVOKED                         = 23;
  X509_V_ERR_INVALID_CA                           = 24;
  X509_V_ERR_PATH_LENGTH_EXCEEDED                 = 25;
  X509_V_ERR_INVALID_PURPOSE                      = 26;
  X509_V_ERR_CERT_UNTRUSTED                       = 27;
  X509_V_ERR_CERT_REJECTED                        = 28;
  (* These are 'informational' when looking for issuer cert *)
  X509_V_ERR_SUBJECT_ISSUER_MISMATCH              = 29;
  X509_V_ERR_AKID_SKID_MISMATCH                   = 30;
  X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH          = 31;
  X509_V_ERR_KEYUSAGE_NO_CERTSIGN                 = 32;
  X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER             = 33;
  X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION         = 34;
  X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                 = 35;
  X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION     = 36;
  X509_V_ERR_INVALID_NON_CA                       = 37;
  X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED           = 38;
  X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE        = 39;
  X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED       = 40;
  X509_V_ERR_INVALID_EXTENSION                    = 41;
  X509_V_ERR_INVALID_POLICY_EXTENSION             = 42;
  X509_V_ERR_NO_EXPLICIT_POLICY                   = 43;
  X509_V_ERR_DIFFERENT_CRL_SCOPE                  = 44;
  X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE        = 45;
  X509_V_ERR_UNNESTED_RESOURCE                    = 46;
  X509_V_ERR_PERMITTED_VIOLATION                  = 47;
  X509_V_ERR_EXCLUDED_VIOLATION                   = 48;
  X509_V_ERR_SUBTREE_MINMAX                       = 49;
  (* The application is not happy *)
  X509_V_ERR_APPLICATION_VERIFICATION             = 50;
  X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE          = 51;
  X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX        = 52;
  X509_V_ERR_UNSUPPORTED_NAME_SYNTAX              = 53;
  X509_V_ERR_CRL_PATH_VALIDATION_ERROR            = 54;
  (* Another issuer check debug option *)
  X509_V_ERR_PATH_LOOP                            = 55;
  (* Suite B mode algorithm violation *)
  X509_V_ERR_SUITE_B_INVALID_VERSION              = 56;
  X509_V_ERR_SUITE_B_INVALID_ALGORITHM            = 57;
  X509_V_ERR_SUITE_B_INVALID_CURVE                = 58;
  X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM  = 59;
  X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED              = 60;
  X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = 61;
  (* Host, email and IP check errors *)
  X509_V_ERR_HOSTNAME_MISMATCH                    = 62;
  X509_V_ERR_EMAIL_MISMATCH                       = 63;
  X509_V_ERR_IP_ADDRESS_MISMATCH                  = 64;
  (* DANE TLSA errors *)
  X509_V_ERR_DANE_NO_MATCH                        = 65;
  (* security level errors *)
  X509_V_ERR_EE_KEY_TOO_SMALL                     = 66;
  X509_V_ERR_CA_KEY_TOO_SMALL                     = 67;
  X509_V_ERR_CA_MD_TOO_WEAK                       = 68;
  (* Caller error *)
  X509_V_ERR_INVALID_CALL                         = 69;
  (* Issuer lookup error *)
  X509_V_ERR_STORE_LOOKUP                         = 70;
  (* Certificate transparency *)
  X509_V_ERR_NO_VALID_SCTS                        = 71;

  X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION         = 72;
  (* OCSP status errors *)
  X509_V_ERR_OCSP_VERIFY_NEEDED                   = 73;  (* Need OCSP verification *)
  X509_V_ERR_OCSP_VERIFY_FAILED                   = 74;  (* Couldn't verify cert through OCSP *)
  X509_V_ERR_OCSP_CERT_UNKNOWN                    = 75;  (* Certificate wasn't recognized by the OCSP responder *)

  (* Certificate verify flags *)

  (* Use check time instead of current time *)
  X509_V_FLAG_USE_CHECK_TIME       = $2;
  (* Lookup CRLs *)
  X509_V_FLAG_CRL_CHECK            = $4;
  (* Lookup CRLs for whole chain *)
  X509_V_FLAG_CRL_CHECK_ALL        = $8;
  (* Ignore unhandled critical extensions *)
  X509_V_FLAG_IGNORE_CRITICAL      = $10;
  (* Disable workarounds for broken certificates *)
  X509_V_FLAG_X509_STRICT          = $20;
  (* Enable proxy certificate validation *)
  X509_V_FLAG_ALLOW_PROXY_CERTS    = $40;
  (* Enable policy checking *)
  X509_V_FLAG_POLICY_CHECK         = $80;
  (* Policy variable require-explicit-policy *)
  X509_V_FLAG_EXPLICIT_POLICY      = $100;
  (* Policy variable inhibit-any-policy *)
  X509_V_FLAG_INHIBIT_ANY          = $200;
  (* Policy variable inhibit-policy-mapping *)
  X509_V_FLAG_INHIBIT_MAP          = $400;
  (* Notify callback that policy is OK *)
  X509_V_FLAG_NOTIFY_POLICY        = $800;
  (* Extended CRL features such as indirect CRLs, alternate CRL signing keys *)
  X509_V_FLAG_EXTENDED_CRL_SUPPORT = $1000;
  (* Delta CRL support *)
  X509_V_FLAG_USE_DELTAS           = $2000;
  (* Check self-signed CA signature *)
  X509_V_FLAG_CHECK_SS_SIGNATURE   = $4000;
  (* Use trusted store first *)
  X509_V_FLAG_TRUSTED_FIRST        = $8000;
  (* Suite B 128 bit only mode: not normally used *)
  X509_V_FLAG_SUITEB_128_LOS_ONLY  = $10000;
  (* Suite B 192 bit only mode *)
  X509_V_FLAG_SUITEB_192_LOS       = $20000;
  (* Suite B 128 bit mode allowing 192 bit algorithms *)
  X509_V_FLAG_SUITEB_128_LOS       = $30000;
  (* Allow partial chains if at least one certificate is in trusted store *)
  X509_V_FLAG_PARTIAL_CHAIN        = $80000;
  (*
   * If the initial chain is not trusted, do not attempt to build an alternative
   * chain. Alternate chain checking was introduced 1.1.0. Setting this flag
   * will force the behaviour to match that of previous versions.
   *)
  X509_V_FLAG_NO_ALT_CHAINS        = $100000;
  (* Do not check certificate/CRL validity against current time *)
  X509_V_FLAG_NO_CHECK_TIME        = $200000;

  X509_VP_FLAG_DEFAULT             = $1;
  X509_VP_FLAG_OVERWRITE           = $2;
  X509_VP_FLAG_RESET_FLAGS         = $4;
  X509_VP_FLAG_LOCKED              = $8;
  X509_VP_FLAG_ONCE                = $10;

  (* Internal use: mask of policy related options *)
  X509_V_FLAG_POLICY_MASK = X509_V_FLAG_POLICY_CHECK or X509_V_FLAG_EXPLICIT_POLICY
    or X509_V_FLAG_INHIBIT_ANY or X509_V_FLAG_INHIBIT_MAP;


  DANE_FLAG_NO_DANE_EE_NAMECHECKS = TOpenSSL_C_Long(1) shl 0;

  (* Non positive return values are errors *)
  X509_PCY_TREE_FAILURE  = -2; (* Failure to satisfy explicit policy *)
  X509_PCY_TREE_INVALID  = -1; (* Inconsistent or invalid extensions *)
  X509_PCY_TREE_INTERNAL = 0; (* Internal error, most likely malloc *)

  (*
   * Positive return values form a bit mask, all but the first are internal to
   * the library and don't appear in results from X509_policy_check().
   *)
  X509_PCY_TREE_VALID    = 1; (* The policy tree is valid *)
  X509_PCY_TREE_EMPTY    = 2; (* The policy tree is empty *)
  X509_PCY_TREE_EXPLICIT = 4; (* Explicit policy required *)

type
  (*-
  SSL_CTX -> X509_STORE
                  -> X509_LOOKUP
                          ->X509_LOOKUP_METHOD
                  -> X509_LOOKUP
                          ->X509_LOOKUP_METHOD

  SSL     -> X509_STORE_CTX
                  ->X509_STORE

  The X509_STORE holds the tables etc for verification stuff.
  A X509_STORE_CTX is used while validating a single certificate.
  The X509_STORE has X509_LOOKUPs for looking up certs.
  The X509_STORE then calls a function to actually verify the
  certificate chain.
  *)

  X509_LOOKUP_TYPE = (
    X509_LU_NONE = 0,
    X509_LU_X509,
    X509_LU_CRL
  );

  X509_STORE_CTX_verify_cb = function(v1: TOpenSSL_C_INT; v2: PX509_STORE_CTX): TOpenSSL_C_INT;
  X509_STORE_CTX_verify_fn = function(v1: PX509_STORE_CTX): TOpenSSL_C_INT;
  X509_STORE_CTX_get_issuer_fn = function(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TOpenSSL_C_INT;
  X509_STORE_CTX_check_issued_fn = function(ctx: PX509_STORE_CTX; x: PX509; issuer: PX509): TOpenSSL_C_INT;
  X509_STORE_CTX_check_revocation_fn = function(ctx: PX509_STORE_CTX): TOpenSSL_C_INT;
  X509_STORE_CTX_get_crl_fn = function(ctx: PX509_STORE_CTX; crl: PPX509_CRL; x: PX509): TOpenSSL_C_INT;
  X509_STORE_CTX_check_crl_fn = function(ctx: PX509_STORE_CTX; crl: PX509_CRL): TOpenSSL_C_INT;
  X509_STORE_CTX_cert_crl_fn = function(ctx: PX509_STORE_CTX; crl: PX509_CRL; x: PX509): TOpenSSL_C_INT;
  X509_STORE_CTX_check_policy_fn = function(ctx: PX509_STORE_CTX): TOpenSSL_C_INT;
//  typedef STACK_OF(X509) *(*X509_STORE_CTX_lookup_certs_fn)(X509_STORE_CTX *ctx,
//                                                            X509_NAME *nm);
//  typedef STACK_OF(X509_CRL) *(*X509_STORE_CTX_lookup_crls_fn)(X509_STORE_CTX *ctx,
//                                                               X509_NAME *nm);
  X509_STORE_CTX_cleanup_fn = function(ctx: PX509_STORE_CTX): TOpenSSL_C_INT;

  X509_LOOKUP_ctrl_fn = function(ctx: PX509_LOOKUP; cmd: TOpenSSL_C_INT;
    const argc: PAnsiChar; argl: TOpenSSL_C_LONG; ret: PPAnsiChar): TOpenSSL_C_INT; cdecl;
  X509_LOOKUP_get_by_subject_fn = function(ctx: PX509_LOOKUP;
    type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
  X509_LOOKUP_get_by_issuer_serial_fn = function(ctx: PX509_LOOKUP;
    type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
  X509_LOOKUP_get_by_fingerprint_fn = function(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE;
    const bytes: PByte; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
  X509_LOOKUP_get_by_alias_fn = function(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE;
    const str: PAnsiChar; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;

  //DEFINE_STACK_OF(X509_LOOKUP)
  //DEFINE_STACK_OF(X509_OBJECT)
  //DEFINE_STACK_OF(X509_VERIFY_PARAM)

  

function X509_LOOKUP_load_file(ctx: PX509_LOOKUP; name: PAnsiChar; type_: TOpenSSL_C_LONG): TOpenSSL_C_INT;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM X509_STORE_set_depth}
{$EXTERNALSYM X509_STORE_CTX_set_depth}
{$EXTERNALSYM X509_OBJECT_up_ref_count}
{$EXTERNALSYM X509_OBJECT_new}
{$EXTERNALSYM X509_OBJECT_free}
{$EXTERNALSYM X509_OBJECT_get_type}
{$EXTERNALSYM X509_OBJECT_get0_X509}
{$EXTERNALSYM X509_OBJECT_set1_X509}
{$EXTERNALSYM X509_OBJECT_get0_X509_CRL}
{$EXTERNALSYM X509_OBJECT_set1_X509_CRL}
{$EXTERNALSYM X509_STORE_new}
{$EXTERNALSYM X509_STORE_free}
{$EXTERNALSYM X509_STORE_lock}
{$EXTERNALSYM X509_STORE_unlock}
{$EXTERNALSYM X509_STORE_up_ref}
{$EXTERNALSYM X509_STORE_set_flags}
{$EXTERNALSYM X509_STORE_set_purpose}
{$EXTERNALSYM X509_STORE_set_trust}
{$EXTERNALSYM X509_STORE_set1_param}
{$EXTERNALSYM X509_STORE_get0_param}
{$EXTERNALSYM X509_STORE_set_verify}
{$EXTERNALSYM X509_STORE_CTX_set_verify}
{$EXTERNALSYM X509_STORE_get_verify}
{$EXTERNALSYM X509_STORE_set_verify_cb}
{$EXTERNALSYM X509_STORE_get_verify_cb}
{$EXTERNALSYM X509_STORE_set_get_issuer}
{$EXTERNALSYM X509_STORE_get_get_issuer}
{$EXTERNALSYM X509_STORE_set_check_issued}
{$EXTERNALSYM X509_STORE_get_check_issued}
{$EXTERNALSYM X509_STORE_set_check_revocation}
{$EXTERNALSYM X509_STORE_get_check_revocation}
{$EXTERNALSYM X509_STORE_set_get_crl}
{$EXTERNALSYM X509_STORE_get_get_crl}
{$EXTERNALSYM X509_STORE_set_check_crl}
{$EXTERNALSYM X509_STORE_get_check_crl}
{$EXTERNALSYM X509_STORE_set_cert_crl}
{$EXTERNALSYM X509_STORE_get_cert_crl}
{$EXTERNALSYM X509_STORE_set_check_policy}
{$EXTERNALSYM X509_STORE_get_check_policy}
{$EXTERNALSYM X509_STORE_set_cleanup}
{$EXTERNALSYM X509_STORE_get_cleanup}
{$EXTERNALSYM X509_STORE_set_ex_data}
{$EXTERNALSYM X509_STORE_get_ex_data}
{$EXTERNALSYM X509_STORE_CTX_new}
{$EXTERNALSYM X509_STORE_CTX_get1_issuer}
{$EXTERNALSYM X509_STORE_CTX_free}
{$EXTERNALSYM X509_STORE_CTX_cleanup}
{$EXTERNALSYM X509_STORE_CTX_get0_store}
{$EXTERNALSYM X509_STORE_CTX_get0_cert}
{$EXTERNALSYM X509_STORE_CTX_set_verify_cb}
{$EXTERNALSYM X509_STORE_CTX_get_verify_cb}
{$EXTERNALSYM X509_STORE_CTX_get_verify}
{$EXTERNALSYM X509_STORE_CTX_get_get_issuer}
{$EXTERNALSYM X509_STORE_CTX_get_check_issued}
{$EXTERNALSYM X509_STORE_CTX_get_check_revocation}
{$EXTERNALSYM X509_STORE_CTX_get_get_crl}
{$EXTERNALSYM X509_STORE_CTX_get_check_crl}
{$EXTERNALSYM X509_STORE_CTX_get_cert_crl}
{$EXTERNALSYM X509_STORE_CTX_get_check_policy}
{$EXTERNALSYM X509_STORE_CTX_get_cleanup}
{$EXTERNALSYM X509_STORE_add_lookup}
{$EXTERNALSYM X509_LOOKUP_hash_dir}
{$EXTERNALSYM X509_LOOKUP_file}
{$EXTERNALSYM X509_LOOKUP_meth_new}
{$EXTERNALSYM X509_LOOKUP_meth_free}
{$EXTERNALSYM X509_LOOKUP_meth_set_ctrl}
{$EXTERNALSYM X509_LOOKUP_meth_get_ctrl}
{$EXTERNALSYM X509_LOOKUP_meth_set_get_by_subject}
{$EXTERNALSYM X509_LOOKUP_meth_get_get_by_subject}
{$EXTERNALSYM X509_LOOKUP_meth_set_get_by_issuer_serial}
{$EXTERNALSYM X509_LOOKUP_meth_get_get_by_issuer_serial}
{$EXTERNALSYM X509_LOOKUP_meth_set_get_by_fingerprint}
{$EXTERNALSYM X509_LOOKUP_meth_get_get_by_fingerprint}
{$EXTERNALSYM X509_LOOKUP_meth_set_get_by_alias}
{$EXTERNALSYM X509_LOOKUP_meth_get_get_by_alias}
{$EXTERNALSYM X509_STORE_add_cert}
{$EXTERNALSYM X509_STORE_add_crl}
{$EXTERNALSYM X509_STORE_CTX_get_by_subject}
{$EXTERNALSYM X509_STORE_CTX_get_obj_by_subject}
{$EXTERNALSYM X509_LOOKUP_ctrl}
{$EXTERNALSYM X509_load_cert_file}
{$EXTERNALSYM X509_load_crl_file}
{$EXTERNALSYM X509_load_cert_crl_file}
{$EXTERNALSYM X509_LOOKUP_new}
{$EXTERNALSYM X509_LOOKUP_free}
{$EXTERNALSYM X509_LOOKUP_init}
{$EXTERNALSYM X509_LOOKUP_by_subject}
{$EXTERNALSYM X509_LOOKUP_by_issuer_serial}
{$EXTERNALSYM X509_LOOKUP_by_fingerprint}
{$EXTERNALSYM X509_LOOKUP_by_alias}
{$EXTERNALSYM X509_LOOKUP_set_method_data}
{$EXTERNALSYM X509_LOOKUP_get_method_data}
{$EXTERNALSYM X509_LOOKUP_get_store}
{$EXTERNALSYM X509_LOOKUP_shutdown}
{$EXTERNALSYM X509_STORE_load_locations}
{$EXTERNALSYM X509_STORE_set_default_paths}
{$EXTERNALSYM X509_STORE_CTX_set_ex_data}
{$EXTERNALSYM X509_STORE_CTX_get_ex_data}
{$EXTERNALSYM X509_STORE_CTX_get_error}
{$EXTERNALSYM X509_STORE_CTX_set_error}
{$EXTERNALSYM X509_STORE_CTX_get_error_depth}
{$EXTERNALSYM X509_STORE_CTX_set_error_depth}
{$EXTERNALSYM X509_STORE_CTX_get_current_cert}
{$EXTERNALSYM X509_STORE_CTX_set_current_cert}
{$EXTERNALSYM X509_STORE_CTX_get0_current_issuer}
{$EXTERNALSYM X509_STORE_CTX_get0_current_crl}
{$EXTERNALSYM X509_STORE_CTX_get0_parent_ctx}
{$EXTERNALSYM X509_STORE_CTX_set_cert}
{$EXTERNALSYM X509_STORE_CTX_set_purpose}
{$EXTERNALSYM X509_STORE_CTX_set_trust}
{$EXTERNALSYM X509_STORE_CTX_purpose_inherit}
{$EXTERNALSYM X509_STORE_CTX_set_flags}
{$EXTERNALSYM X509_STORE_CTX_get0_policy_tree}
{$EXTERNALSYM X509_STORE_CTX_get_explicit_policy}
{$EXTERNALSYM X509_STORE_CTX_get_num_untrusted}
{$EXTERNALSYM X509_STORE_CTX_get0_param}
{$EXTERNALSYM X509_STORE_CTX_set0_param}
{$EXTERNALSYM X509_STORE_CTX_set_default}
{$EXTERNALSYM X509_STORE_CTX_set0_dane}
{$EXTERNALSYM X509_VERIFY_PARAM_new}
{$EXTERNALSYM X509_VERIFY_PARAM_free}
{$EXTERNALSYM X509_VERIFY_PARAM_inherit}
{$EXTERNALSYM X509_VERIFY_PARAM_set1}
{$EXTERNALSYM X509_VERIFY_PARAM_set1_name}
{$EXTERNALSYM X509_VERIFY_PARAM_set_flags}
{$EXTERNALSYM X509_VERIFY_PARAM_clear_flags}
{$EXTERNALSYM X509_VERIFY_PARAM_get_flags}
{$EXTERNALSYM X509_VERIFY_PARAM_set_purpose}
{$EXTERNALSYM X509_VERIFY_PARAM_set_trust}
{$EXTERNALSYM X509_VERIFY_PARAM_set_depth}
{$EXTERNALSYM X509_VERIFY_PARAM_set_auth_level}
{$EXTERNALSYM X509_VERIFY_PARAM_add0_policy}
{$EXTERNALSYM X509_VERIFY_PARAM_set_inh_flags}
{$EXTERNALSYM X509_VERIFY_PARAM_get_inh_flags}
{$EXTERNALSYM X509_VERIFY_PARAM_set1_host}
{$EXTERNALSYM X509_VERIFY_PARAM_add1_host}
{$EXTERNALSYM X509_VERIFY_PARAM_set_hostflags}
{$EXTERNALSYM X509_VERIFY_PARAM_get_hostflags}
{$EXTERNALSYM X509_VERIFY_PARAM_get0_peername}
{$EXTERNALSYM X509_VERIFY_PARAM_move_peername}
{$EXTERNALSYM X509_VERIFY_PARAM_set1_email}
{$EXTERNALSYM X509_VERIFY_PARAM_set1_ip}
{$EXTERNALSYM X509_VERIFY_PARAM_set1_ip_asc}
{$EXTERNALSYM X509_VERIFY_PARAM_get_depth}
{$EXTERNALSYM X509_VERIFY_PARAM_get_auth_level}
{$EXTERNALSYM X509_VERIFY_PARAM_get0_name}
{$EXTERNALSYM X509_VERIFY_PARAM_add0_table}
{$EXTERNALSYM X509_VERIFY_PARAM_get_count}
{$EXTERNALSYM X509_VERIFY_PARAM_get0}
{$EXTERNALSYM X509_VERIFY_PARAM_lookup}
{$EXTERNALSYM X509_VERIFY_PARAM_table_cleanup}
{$EXTERNALSYM X509_policy_tree_free}
{$EXTERNALSYM X509_policy_tree_level_count}
{$EXTERNALSYM X509_policy_tree_get0_level}
{$EXTERNALSYM X509_policy_level_node_count}
{$EXTERNALSYM X509_policy_level_get0_node}
{$EXTERNALSYM X509_policy_node_get0_policy}
{$EXTERNALSYM X509_policy_node_get0_parent}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function X509_STORE_set_depth(store: PX509_STORE; depth: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_depth(ctx: PX509_STORE_CTX; depth: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function X509_OBJECT_up_ref_count(a: PX509_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_OBJECT_new: PX509_OBJECT; cdecl; external CLibCrypto;
procedure X509_OBJECT_free(a: PX509_OBJECT); cdecl; external CLibCrypto;
function X509_OBJECT_get_type(const a: PX509_OBJECT): X509_LOOKUP_TYPE; cdecl; external CLibCrypto;
function X509_OBJECT_get0_X509(const a: PX509_OBJECT): PX509; cdecl; external CLibCrypto;
function X509_OBJECT_set1_X509(a: PX509_OBJECT; obj: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_OBJECT_get0_X509_CRL(a: PX509_OBJECT): PX509_CRL; cdecl; external CLibCrypto;
function X509_OBJECT_set1_X509_CRL(a: PX509_OBJECT; obj: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_new: PX509_STORE; cdecl; external CLibCrypto;
procedure X509_STORE_free(v: PX509_STORE); cdecl; external CLibCrypto;
function X509_STORE_lock(ctx: PX509_STORE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_unlock(ctx: PX509_STORE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_up_ref(v: PX509_STORE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_set_flags(ctx: PX509_STORE; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_set_purpose(ctx: PX509_STORE; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_set_trust(ctx: PX509_STORE; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_set1_param(ctx: PX509_STORE; pm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_get0_param(ctx: PX509_STORE): PX509_VERIFY_PARAM; cdecl; external CLibCrypto;
procedure X509_STORE_set_verify(ctx: PX509_STORE; verify: X509_STORE_CTX_verify_fn); cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_verify(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_fn); cdecl; external CLibCrypto;
function X509_STORE_get_verify(ctx: PX509_STORE): X509_STORE_CTX_verify_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_verify_cb(ctx: PX509_STORE; verify_cb: X509_STORE_CTX_verify_cb); cdecl; external CLibCrypto;
function X509_STORE_get_verify_cb(ctx: PX509_STORE): X509_STORE_CTX_verify_cb; cdecl; external CLibCrypto;
procedure X509_STORE_set_get_issuer(ctx: PX509_STORE; get_issuer: X509_STORE_CTX_get_issuer_fn); cdecl; external CLibCrypto;
function X509_STORE_get_get_issuer(ctx: PX509_STORE): X509_STORE_CTX_get_issuer_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_check_issued(ctx: PX509_STORE; check_issued: X509_STORE_CTX_check_issued_fn); cdecl; external CLibCrypto;
function X509_STORE_get_check_issued(ctx: PX509_STORE): X509_STORE_CTX_check_issued_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_check_revocation(ctx: PX509_STORE; check_revocation: X509_STORE_CTX_check_revocation_fn); cdecl; external CLibCrypto;
function X509_STORE_get_check_revocation(ctx: PX509_STORE): X509_STORE_CTX_check_revocation_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_get_crl(ctx: PX509_STORE; get_crl: X509_STORE_CTX_get_crl_fn); cdecl; external CLibCrypto;
function X509_STORE_get_get_crl(ctx: PX509_STORE): X509_STORE_CTX_get_crl_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_check_crl(ctx: PX509_STORE; check_crl: X509_STORE_CTX_check_crl_fn); cdecl; external CLibCrypto;
function X509_STORE_get_check_crl(ctx: PX509_STORE): X509_STORE_CTX_check_crl_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_cert_crl(ctx: PX509_STORE; cert_crl: X509_STORE_CTX_cert_crl_fn); cdecl; external CLibCrypto;
function X509_STORE_get_cert_crl(ctx: PX509_STORE): X509_STORE_CTX_cert_crl_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_check_policy(ctx: PX509_STORE; check_policy: X509_STORE_CTX_check_policy_fn); cdecl; external CLibCrypto;
function X509_STORE_get_check_policy(ctx: PX509_STORE): X509_STORE_CTX_check_policy_fn; cdecl; external CLibCrypto;
procedure X509_STORE_set_cleanup(ctx: PX509_STORE; cleanup: X509_STORE_CTX_cleanup_fn); cdecl; external CLibCrypto;
function X509_STORE_get_cleanup(ctx: PX509_STORE): X509_STORE_CTX_cleanup_fn; cdecl; external CLibCrypto;
function X509_STORE_set_ex_data(ctx: PX509_STORE; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_get_ex_data(ctx: PX509_STORE; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_STORE_CTX_new: PX509_STORE_CTX; cdecl; external CLibCrypto;
function X509_STORE_CTX_get1_issuer(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_free(ctx: PX509_STORE_CTX); cdecl; external CLibCrypto;
procedure X509_STORE_CTX_cleanup(ctx: PX509_STORE_CTX); cdecl; external CLibCrypto;
function X509_STORE_CTX_get0_store(ctx: PX509_STORE_CTX): PX509_STORE; cdecl; external CLibCrypto;
function X509_STORE_CTX_get0_cert(ctx: PX509_STORE_CTX): PX509; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_verify_cb(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_cb); cdecl; external CLibCrypto;
function X509_STORE_CTX_get_verify_cb(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_cb; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_verify(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_get_issuer(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_issuer_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_check_issued(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_issued_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_check_revocation(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_revocation_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_get_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_crl_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_check_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_crl_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_cert_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_cert_crl_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_check_policy(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_policy_fn; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_cleanup(ctx: PX509_STORE_CTX): X509_STORE_CTX_cleanup_fn; cdecl; external CLibCrypto;
function X509_STORE_add_lookup(v: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl; external CLibCrypto;
function X509_LOOKUP_hash_dir: PX509_LOOKUP_METHOD; cdecl; external CLibCrypto;
function X509_LOOKUP_file: PX509_LOOKUP_METHOD; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_new(const name: PAnsiChar): PX509_LOOKUP_METHOD; cdecl; external CLibCrypto;
procedure X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD); cdecl; external CLibCrypto;
function X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_get_ctrl(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_ctrl_fn; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_set_get_by_subject(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_subject_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_get_get_by_subject(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_subject_fn; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_set_get_by_issuer_serial(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_issuer_serial_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_get_get_by_issuer_serial(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_issuer_serial_fn; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_set_get_by_fingerprint(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_fingerprint_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_get_get_by_fingerprint(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_fingerprint_fn; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_set_get_by_alias(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_alias_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_meth_get_get_by_alias(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_alias_fn; cdecl; external CLibCrypto;
function X509_STORE_add_cert(ctx: PX509_STORE; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_add_crl(ctx: PX509_STORE; x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_obj_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl; external CLibCrypto;
function X509_LOOKUP_ctrl(ctx: PX509_LOOKUP; cmd: TOpenSSL_C_INT; const argc: PAnsiChar; argl: TOpenSSL_C_LONG; ret: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_load_cert_file(ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_load_crl_file(ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_load_cert_crl_file(ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_new(method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl; external CLibCrypto;
procedure X509_LOOKUP_free(ctx: PX509_LOOKUP); cdecl; external CLibCrypto;
function X509_LOOKUP_init(ctx: PX509_LOOKUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_by_subject(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_by_issuer_serial(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_by_fingerprint(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const bytes: PByte; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_by_alias(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const str: PAnsiChar; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_set_method_data(ctx: PX509_LOOKUP; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_LOOKUP_get_method_data(const ctx: PX509_LOOKUP): Pointer; cdecl; external CLibCrypto;
function X509_LOOKUP_get_store(const ctx: PX509_LOOKUP): PX509_STORE; cdecl; external CLibCrypto;
function X509_LOOKUP_shutdown(ctx: PX509_LOOKUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_load_locations(ctx: PX509_STORE; const file_: PAnsiChar; const dir: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_set_default_paths(ctx: PX509_STORE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_set_ex_data(ctx: PX509_STORE_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_ex_data(ctx: PX509_STORE_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_error(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_error(ctx: X509_STORE_CTX; s: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function X509_STORE_CTX_get_error_depth(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_error_depth(ctx: PX509_STORE_CTX; depth: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function X509_STORE_CTX_get_current_cert(ctx: PX509_STORE_CTX): PX509; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_current_cert(ctx: PX509_STORE_CTX; x: PX509); cdecl; external CLibCrypto;
function X509_STORE_CTX_get0_current_issuer(ctx: PX509_STORE_CTX): PX509; cdecl; external CLibCrypto;
function X509_STORE_CTX_get0_current_crl(ctx: PX509_STORE_CTX): PX509_CRL; cdecl; external CLibCrypto;
function X509_STORE_CTX_get0_parent_ctx(ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_cert(c: PX509_STORE_CTX; x: PX509); cdecl; external CLibCrypto;
function X509_STORE_CTX_set_purpose(ctx: PX509_STORE_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_set_trust(ctx: PX509_STORE_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_purpose_inherit(ctx: PX509_STORE_CTX; def_purpose: TOpenSSL_C_INT; purpose: TOpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set_flags(ctx: PX509_STORE_CTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function X509_STORE_CTX_get0_policy_tree(ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_explicit_policy(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_get_num_untrusted(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_STORE_CTX_get0_param(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set0_param(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM); cdecl; external CLibCrypto;
function X509_STORE_CTX_set_default(ctx: PX509_STORE_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_STORE_CTX_set0_dane(ctx: PX509_STORE_CTX; dane: PSSL_DANE); cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_new: PX509_VERIFY_PARAM; cdecl; external CLibCrypto;
procedure X509_VERIFY_PARAM_free(param: PX509_VERIFY_PARAM); cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_inherit(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set1(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set1_name(param: PX509_VERIFY_PARAM; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set_flags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_clear_flags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get_flags(param: PX509_VERIFY_PARAM): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set_purpose(param: PX509_VERIFY_PARAM; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set_trust(param: PX509_VERIFY_PARAM; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_VERIFY_PARAM_set_depth(param: PX509_VERIFY_PARAM; depth: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure X509_VERIFY_PARAM_set_auth_level(param: PX509_VERIFY_PARAM; auth_level: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_add0_policy(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set_inh_flags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get_inh_flags(const param: PX509_VERIFY_PARAM): TOpenSSL_C_UINT32; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set1_host(param: PX509_VERIFY_PARAM; const name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_add1_host(param: PX509_VERIFY_PARAM; const name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_VERIFY_PARAM_set_hostflags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_UINT); cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get_hostflags(const param: PX509_VERIFY_PARAM): TOpenSSL_C_UINT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get0_peername(v1: PX509_VERIFY_PARAM): PAnsiChar; cdecl; external CLibCrypto;
procedure X509_VERIFY_PARAM_move_peername(v1: PX509_VERIFY_PARAM; v2: PX509_VERIFY_PARAM); cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set1_email(param: PX509_VERIFY_PARAM; const email: PAnsiChar; emaillen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set1_ip(param: PX509_VERIFY_PARAM; const ip: PByte; iplen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_set1_ip_asc(param: PX509_VERIFY_PARAM; const ipasc: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get_depth(const param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get_auth_level(const param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get0_name(const param: PX509_VERIFY_PARAM): PAnsiChar; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_add0_table(param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get_count: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_get0(id: TOpenSSL_C_INT): PX509_VERIFY_PARAM; cdecl; external CLibCrypto;
function X509_VERIFY_PARAM_lookup(const name: PAnsiChar): X509_VERIFY_PARAM; cdecl; external CLibCrypto;
procedure X509_VERIFY_PARAM_table_cleanup; cdecl; external CLibCrypto;
procedure X509_policy_tree_free(tree: PX509_POLICY_TREE); cdecl; external CLibCrypto;
function X509_policy_tree_level_count(const tree: PX509_POLICY_TREE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_policy_tree_get0_level(const tree: PX509_POLICY_TREE; i: TOpenSSL_C_INT): PX509_POLICY_LEVEL; cdecl; external CLibCrypto;
function X509_policy_level_node_count(level: PX509_POLICY_LEVEL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_policy_level_get0_node(level: PX509_POLICY_LEVEL; i: TOpenSSL_C_INT): PX509_POLICY_NODE; cdecl; external CLibCrypto;
function X509_policy_node_get0_policy(const node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl; external CLibCrypto;
function X509_policy_node_get0_parent(const node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl; external CLibCrypto;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  X509_STORE_set_depth: function (store: PX509_STORE; depth: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_set_depth: procedure (ctx: PX509_STORE_CTX; depth: TOpenSSL_C_INT); cdecl = nil;
  X509_OBJECT_up_ref_count: function (a: PX509_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_OBJECT_new: function : PX509_OBJECT; cdecl = nil;
  X509_OBJECT_free: procedure (a: PX509_OBJECT); cdecl = nil;
  X509_OBJECT_get_type: function (const a: PX509_OBJECT): X509_LOOKUP_TYPE; cdecl = nil;
  X509_OBJECT_get0_X509: function (const a: PX509_OBJECT): PX509; cdecl = nil;
  X509_OBJECT_set1_X509: function (a: PX509_OBJECT; obj: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_OBJECT_get0_X509_CRL: function (a: PX509_OBJECT): PX509_CRL; cdecl = nil;
  X509_OBJECT_set1_X509_CRL: function (a: PX509_OBJECT; obj: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_new: function : PX509_STORE; cdecl = nil;
  X509_STORE_free: procedure (v: PX509_STORE); cdecl = nil;
  X509_STORE_lock: function (ctx: PX509_STORE): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_unlock: function (ctx: PX509_STORE): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_up_ref: function (v: PX509_STORE): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_set_flags: function (ctx: PX509_STORE; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_set_purpose: function (ctx: PX509_STORE; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_set_trust: function (ctx: PX509_STORE; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_set1_param: function (ctx: PX509_STORE; pm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_get0_param: function (ctx: PX509_STORE): PX509_VERIFY_PARAM; cdecl = nil;
  X509_STORE_set_verify: procedure (ctx: PX509_STORE; verify: X509_STORE_CTX_verify_fn); cdecl = nil;
  X509_STORE_CTX_set_verify: procedure (ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_fn); cdecl = nil;
  X509_STORE_get_verify: function (ctx: PX509_STORE): X509_STORE_CTX_verify_fn; cdecl = nil;
  X509_STORE_set_verify_cb: procedure (ctx: PX509_STORE; verify_cb: X509_STORE_CTX_verify_cb); cdecl = nil;
  X509_STORE_get_verify_cb: function (ctx: PX509_STORE): X509_STORE_CTX_verify_cb; cdecl = nil;
  X509_STORE_set_get_issuer: procedure (ctx: PX509_STORE; get_issuer: X509_STORE_CTX_get_issuer_fn); cdecl = nil;
  X509_STORE_get_get_issuer: function (ctx: PX509_STORE): X509_STORE_CTX_get_issuer_fn; cdecl = nil;
  X509_STORE_set_check_issued: procedure (ctx: PX509_STORE; check_issued: X509_STORE_CTX_check_issued_fn); cdecl = nil;
  X509_STORE_get_check_issued: function (ctx: PX509_STORE): X509_STORE_CTX_check_issued_fn; cdecl = nil;
  X509_STORE_set_check_revocation: procedure (ctx: PX509_STORE; check_revocation: X509_STORE_CTX_check_revocation_fn); cdecl = nil;
  X509_STORE_get_check_revocation: function (ctx: PX509_STORE): X509_STORE_CTX_check_revocation_fn; cdecl = nil;
  X509_STORE_set_get_crl: procedure (ctx: PX509_STORE; get_crl: X509_STORE_CTX_get_crl_fn); cdecl = nil;
  X509_STORE_get_get_crl: function (ctx: PX509_STORE): X509_STORE_CTX_get_crl_fn; cdecl = nil;
  X509_STORE_set_check_crl: procedure (ctx: PX509_STORE; check_crl: X509_STORE_CTX_check_crl_fn); cdecl = nil;
  X509_STORE_get_check_crl: function (ctx: PX509_STORE): X509_STORE_CTX_check_crl_fn; cdecl = nil;
  X509_STORE_set_cert_crl: procedure (ctx: PX509_STORE; cert_crl: X509_STORE_CTX_cert_crl_fn); cdecl = nil;
  X509_STORE_get_cert_crl: function (ctx: PX509_STORE): X509_STORE_CTX_cert_crl_fn; cdecl = nil;
  X509_STORE_set_check_policy: procedure (ctx: PX509_STORE; check_policy: X509_STORE_CTX_check_policy_fn); cdecl = nil;
  X509_STORE_get_check_policy: function (ctx: PX509_STORE): X509_STORE_CTX_check_policy_fn; cdecl = nil;
  X509_STORE_set_cleanup: procedure (ctx: PX509_STORE; cleanup: X509_STORE_CTX_cleanup_fn); cdecl = nil;
  X509_STORE_get_cleanup: function (ctx: PX509_STORE): X509_STORE_CTX_cleanup_fn; cdecl = nil;
  X509_STORE_set_ex_data: function (ctx: PX509_STORE; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_get_ex_data: function (ctx: PX509_STORE; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  X509_STORE_CTX_new: function : PX509_STORE_CTX; cdecl = nil;
  X509_STORE_CTX_get1_issuer: function (issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_free: procedure (ctx: PX509_STORE_CTX); cdecl = nil;
  X509_STORE_CTX_cleanup: procedure (ctx: PX509_STORE_CTX); cdecl = nil;
  X509_STORE_CTX_get0_store: function (ctx: PX509_STORE_CTX): PX509_STORE; cdecl = nil;
  X509_STORE_CTX_get0_cert: function (ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  X509_STORE_CTX_set_verify_cb: procedure (ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_cb); cdecl = nil;
  X509_STORE_CTX_get_verify_cb: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_cb; cdecl = nil;
  X509_STORE_CTX_get_verify: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_fn; cdecl = nil;
  X509_STORE_CTX_get_get_issuer: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_get_issuer_fn; cdecl = nil;
  X509_STORE_CTX_get_check_issued: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_issued_fn; cdecl = nil;
  X509_STORE_CTX_get_check_revocation: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_revocation_fn; cdecl = nil;
  X509_STORE_CTX_get_get_crl: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_get_crl_fn; cdecl = nil;
  X509_STORE_CTX_get_check_crl: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_crl_fn; cdecl = nil;
  X509_STORE_CTX_get_cert_crl: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_cert_crl_fn; cdecl = nil;
  X509_STORE_CTX_get_check_policy: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_policy_fn; cdecl = nil;
  X509_STORE_CTX_get_cleanup: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_cleanup_fn; cdecl = nil;
  X509_STORE_add_lookup: function (v: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl = nil;
  X509_LOOKUP_hash_dir: function : PX509_LOOKUP_METHOD; cdecl = nil;
  X509_LOOKUP_file: function : PX509_LOOKUP_METHOD; cdecl = nil;
  X509_LOOKUP_meth_new: function (const name: PAnsiChar): PX509_LOOKUP_METHOD; cdecl = nil;
  X509_LOOKUP_meth_free: procedure (method: PX509_LOOKUP_METHOD); cdecl = nil;
  X509_LOOKUP_meth_set_ctrl: function (method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_meth_get_ctrl: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_ctrl_fn; cdecl = nil;
  X509_LOOKUP_meth_set_get_by_subject: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_subject_fn): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_meth_get_get_by_subject: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_subject_fn; cdecl = nil;
  X509_LOOKUP_meth_set_get_by_issuer_serial: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_issuer_serial_fn): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_meth_get_get_by_issuer_serial: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_issuer_serial_fn; cdecl = nil;
  X509_LOOKUP_meth_set_get_by_fingerprint: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_fingerprint_fn): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_meth_get_get_by_fingerprint: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_fingerprint_fn; cdecl = nil;
  X509_LOOKUP_meth_set_get_by_alias: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_alias_fn): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_meth_get_get_by_alias: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_alias_fn; cdecl = nil;
  X509_STORE_add_cert: function (ctx: PX509_STORE; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_add_crl: function (ctx: PX509_STORE; x: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_get_by_subject: function (vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_get_obj_by_subject: function (vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl = nil;
  X509_LOOKUP_ctrl: function (ctx: PX509_LOOKUP; cmd: TOpenSSL_C_INT; const argc: PAnsiChar; argl: TOpenSSL_C_LONG; ret: PPAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  X509_load_cert_file: function (ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_load_crl_file: function (ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_load_cert_crl_file: function (ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_new: function (method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl = nil;
  X509_LOOKUP_free: procedure (ctx: PX509_LOOKUP); cdecl = nil;
  X509_LOOKUP_init: function (ctx: PX509_LOOKUP): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_by_subject: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_by_issuer_serial: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_by_fingerprint: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const bytes: PByte; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_by_alias: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const str: PAnsiChar; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_set_method_data: function (ctx: PX509_LOOKUP; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  X509_LOOKUP_get_method_data: function (const ctx: PX509_LOOKUP): Pointer; cdecl = nil;
  X509_LOOKUP_get_store: function (const ctx: PX509_LOOKUP): PX509_STORE; cdecl = nil;
  X509_LOOKUP_shutdown: function (ctx: PX509_LOOKUP): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_load_locations: function (ctx: PX509_STORE; const file_: PAnsiChar; const dir: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_set_default_paths: function (ctx: PX509_STORE): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_set_ex_data: function (ctx: PX509_STORE_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_get_ex_data: function (ctx: PX509_STORE_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  X509_STORE_CTX_get_error: function (ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_set_error: procedure (ctx: X509_STORE_CTX; s: TOpenSSL_C_INT); cdecl = nil;
  X509_STORE_CTX_get_error_depth: function (ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_set_error_depth: procedure (ctx: PX509_STORE_CTX; depth: TOpenSSL_C_INT); cdecl = nil;
  X509_STORE_CTX_get_current_cert: function (ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  X509_STORE_CTX_set_current_cert: procedure (ctx: PX509_STORE_CTX; x: PX509); cdecl = nil;
  X509_STORE_CTX_get0_current_issuer: function (ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  X509_STORE_CTX_get0_current_crl: function (ctx: PX509_STORE_CTX): PX509_CRL; cdecl = nil;
  X509_STORE_CTX_get0_parent_ctx: function (ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl = nil;
  X509_STORE_CTX_set_cert: procedure (c: PX509_STORE_CTX; x: PX509); cdecl = nil;
  X509_STORE_CTX_set_purpose: function (ctx: PX509_STORE_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_set_trust: function (ctx: PX509_STORE_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_purpose_inherit: function (ctx: PX509_STORE_CTX; def_purpose: TOpenSSL_C_INT; purpose: TOpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_set_flags: procedure (ctx: PX509_STORE_CTX; flags: TOpenSSL_C_ULONG); cdecl = nil;
  X509_STORE_CTX_get0_policy_tree: function (ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl = nil;
  X509_STORE_CTX_get_explicit_policy: function (ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_get_num_untrusted: function (ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_get0_param: function (ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl = nil;
  X509_STORE_CTX_set0_param: procedure (ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM); cdecl = nil;
  X509_STORE_CTX_set_default: function (ctx: PX509_STORE_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  X509_STORE_CTX_set0_dane: procedure (ctx: PX509_STORE_CTX; dane: PSSL_DANE); cdecl = nil;
  X509_VERIFY_PARAM_new: function : PX509_VERIFY_PARAM; cdecl = nil;
  X509_VERIFY_PARAM_free: procedure (param: PX509_VERIFY_PARAM); cdecl = nil;
  X509_VERIFY_PARAM_inherit: function (to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1: function (to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1_name: function (param: PX509_VERIFY_PARAM; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_flags: function (param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_clear_flags: function (param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_flags: function (param: PX509_VERIFY_PARAM): TOpenSSL_C_ULONG; cdecl = nil;
  X509_VERIFY_PARAM_set_purpose: function (param: PX509_VERIFY_PARAM; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_trust: function (param: PX509_VERIFY_PARAM; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_depth: procedure (param: PX509_VERIFY_PARAM; depth: TOpenSSL_C_INT); cdecl = nil;
  X509_VERIFY_PARAM_set_auth_level: procedure (param: PX509_VERIFY_PARAM; auth_level: TOpenSSL_C_INT); cdecl = nil;
  X509_VERIFY_PARAM_add0_policy: function (param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_inh_flags: function (param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_inh_flags: function (const param: PX509_VERIFY_PARAM): TOpenSSL_C_UINT32; cdecl = nil;
  X509_VERIFY_PARAM_set1_host: function (param: PX509_VERIFY_PARAM; const name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_add1_host: function (param: PX509_VERIFY_PARAM; const name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_hostflags: procedure (param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_UINT); cdecl = nil;
  X509_VERIFY_PARAM_get_hostflags: function (const param: PX509_VERIFY_PARAM): TOpenSSL_C_UINT; cdecl = nil;
  X509_VERIFY_PARAM_get0_peername: function (v1: PX509_VERIFY_PARAM): PAnsiChar; cdecl = nil;
  X509_VERIFY_PARAM_move_peername: procedure (v1: PX509_VERIFY_PARAM; v2: PX509_VERIFY_PARAM); cdecl = nil;
  X509_VERIFY_PARAM_set1_email: function (param: PX509_VERIFY_PARAM; const email: PAnsiChar; emaillen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1_ip: function (param: PX509_VERIFY_PARAM; const ip: PByte; iplen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1_ip_asc: function (param: PX509_VERIFY_PARAM; const ipasc: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_depth: function (const param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_auth_level: function (const param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_get0_name: function (const param: PX509_VERIFY_PARAM): PAnsiChar; cdecl = nil;
  X509_VERIFY_PARAM_add0_table: function (param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_count: function : TOpenSSL_C_INT; cdecl = nil;
  X509_VERIFY_PARAM_get0: function (id: TOpenSSL_C_INT): PX509_VERIFY_PARAM; cdecl = nil;
  X509_VERIFY_PARAM_lookup: function (const name: PAnsiChar): X509_VERIFY_PARAM; cdecl = nil;
  X509_VERIFY_PARAM_table_cleanup: procedure ; cdecl = nil;
  X509_policy_tree_free: procedure (tree: PX509_POLICY_TREE); cdecl = nil;
  X509_policy_tree_level_count: function (const tree: PX509_POLICY_TREE): TOpenSSL_C_INT; cdecl = nil;
  X509_policy_tree_get0_level: function (const tree: PX509_POLICY_TREE; i: TOpenSSL_C_INT): PX509_POLICY_LEVEL; cdecl = nil;
  X509_policy_level_node_count: function (level: PX509_POLICY_LEVEL): TOpenSSL_C_INT; cdecl = nil;
  X509_policy_level_get0_node: function (level: PX509_POLICY_LEVEL; i: TOpenSSL_C_INT): PX509_POLICY_NODE; cdecl = nil;
  X509_policy_node_get0_policy: function (const node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl = nil;
  X509_policy_node_get0_parent: function (const node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl = nil;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  X509_STORE_CTX_get_app_data: function (ctx: PX509_STORE_CTX): Pointer; cdecl = nil; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  X509_STORE_CTX_get_app_data_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  X509_OBJECT_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_OBJECT_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_OBJECT_get_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_OBJECT_get0_X509_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_OBJECT_set1_X509_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_OBJECT_get0_X509_CRL_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_OBJECT_set1_X509_CRL_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_lock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_unlock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get0_param_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_set_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_verify_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_get_issuer_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_get_issuer_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_check_issued_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_check_issued_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_check_revocation_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_check_revocation_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_get_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_get_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_check_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_check_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_cert_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_cert_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_check_policy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_check_policy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_set_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_get_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get0_cert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_verify_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_get_issuer_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_check_issued_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_check_revocation_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_get_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_check_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_cert_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_check_policy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_set_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_get_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_subject_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_subject_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_issuer_serial_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_issuer_serial_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_fingerprint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_fingerprint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_alias_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_alias_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_by_subject_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_obj_by_subject_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_set_method_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_get_method_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_LOOKUP_get_store_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_set_error_depth_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_set_current_cert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_get_num_untrusted_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_STORE_CTX_set0_dane_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_VERIFY_PARAM_set_auth_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_VERIFY_PARAM_set_inh_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_VERIFY_PARAM_get_inh_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_VERIFY_PARAM_get_hostflags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_VERIFY_PARAM_move_peername_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_VERIFY_PARAM_get_auth_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation


uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$MINENUMSIZE 4}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
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
  Indy_x509_unicode_file_lookup: _X509_LOOKUP_METHOD =
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


type
  _PX509_LOOKUP = ^_X509_LOOKUP;
  _X509_LOOKUP = record
    init: TOpenSSL_C_INT;
    skip: TOpenSSL_C_INT;
    method: PX509_LOOKUP_METHOD;
    method_data: PAnsiChar;
    store_ctx: PX509_STORE;
  end;



function X509_LOOKUP_load_file(ctx: PX509_LOOKUP; name: PAnsiChar; type_: TOpenSSL_C_LONG): TOpenSSL_C_INT;
begin
  Result := X509_LOOKUP_ctrl(ctx,X509_L_FILE_LOAD,name,type_,nil);
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer;

begin
  Result := X509_STORE_CTX_get_ex_data(ctx,SSL_get_ex_data_X509_STORE_CTX_idx);
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer; cdecl;

begin
  Result := X509_STORE_CTX_get_ex_data(ctx,SSL_get_ex_data_X509_STORE_CTX_idx);
end;


function COMPAT_X509_LOOKUP_meth_new(const name: PAnsiChar): PX509_LOOKUP_METHOD; cdecl;

begin
  Result := @Indy_x509_unicode_file_lookup;
end;



procedure COMPAT_X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD); cdecl;

begin
  //Do nothing
end;



function COMPAT_X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TOpenSSL_C_INT; cdecl;

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


function COMPAT_X509_LOOKUP_get_store(const ctx: PX509_LOOKUP): PX509_STORE; cdecl;

begin
  Result := _PX509_LOOKUP(ctx)^.store_ctx;
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$MINENUMSIZE 4}
function ERROR_X509_STORE_set_depth(store: PX509_STORE; depth: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_depth');
end;

procedure ERROR_X509_STORE_CTX_set_depth(ctx: PX509_STORE_CTX; depth: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_depth');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_app_data');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_OBJECT_up_ref_count(a: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_up_ref_count');
end;

function ERROR_X509_OBJECT_new: PX509_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_new');
end;

procedure ERROR_X509_OBJECT_free(a: PX509_OBJECT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_free');
end;

function ERROR_X509_OBJECT_get_type(const a: PX509_OBJECT): X509_LOOKUP_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_get_type');
end;

function ERROR_X509_OBJECT_get0_X509(const a: PX509_OBJECT): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_get0_X509');
end;

function ERROR_X509_OBJECT_set1_X509(a: PX509_OBJECT; obj: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_set1_X509');
end;

function ERROR_X509_OBJECT_get0_X509_CRL(a: PX509_OBJECT): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_get0_X509_CRL');
end;

function ERROR_X509_OBJECT_set1_X509_CRL(a: PX509_OBJECT; obj: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_OBJECT_set1_X509_CRL');
end;

function ERROR_X509_STORE_new: PX509_STORE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_new');
end;

procedure ERROR_X509_STORE_free(v: PX509_STORE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_free');
end;

function ERROR_X509_STORE_lock(ctx: PX509_STORE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_lock');
end;

function ERROR_X509_STORE_unlock(ctx: PX509_STORE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_unlock');
end;

function ERROR_X509_STORE_up_ref(v: PX509_STORE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_up_ref');
end;

function ERROR_X509_STORE_set_flags(ctx: PX509_STORE; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_flags');
end;

function ERROR_X509_STORE_set_purpose(ctx: PX509_STORE; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_purpose');
end;

function ERROR_X509_STORE_set_trust(ctx: PX509_STORE; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_trust');
end;

function ERROR_X509_STORE_set1_param(ctx: PX509_STORE; pm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set1_param');
end;

function ERROR_X509_STORE_get0_param(ctx: PX509_STORE): PX509_VERIFY_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get0_param');
end;

procedure ERROR_X509_STORE_set_verify(ctx: PX509_STORE; verify: X509_STORE_CTX_verify_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_verify');
end;

procedure ERROR_X509_STORE_CTX_set_verify(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_verify');
end;

function ERROR_X509_STORE_get_verify(ctx: PX509_STORE): X509_STORE_CTX_verify_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_verify');
end;

procedure ERROR_X509_STORE_set_verify_cb(ctx: PX509_STORE; verify_cb: X509_STORE_CTX_verify_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_verify_cb');
end;

function ERROR_X509_STORE_get_verify_cb(ctx: PX509_STORE): X509_STORE_CTX_verify_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_verify_cb');
end;

procedure ERROR_X509_STORE_set_get_issuer(ctx: PX509_STORE; get_issuer: X509_STORE_CTX_get_issuer_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_get_issuer');
end;

function ERROR_X509_STORE_get_get_issuer(ctx: PX509_STORE): X509_STORE_CTX_get_issuer_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_get_issuer');
end;

procedure ERROR_X509_STORE_set_check_issued(ctx: PX509_STORE; check_issued: X509_STORE_CTX_check_issued_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_check_issued');
end;

function ERROR_X509_STORE_get_check_issued(ctx: PX509_STORE): X509_STORE_CTX_check_issued_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_check_issued');
end;

procedure ERROR_X509_STORE_set_check_revocation(ctx: PX509_STORE; check_revocation: X509_STORE_CTX_check_revocation_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_check_revocation');
end;

function ERROR_X509_STORE_get_check_revocation(ctx: PX509_STORE): X509_STORE_CTX_check_revocation_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_check_revocation');
end;

procedure ERROR_X509_STORE_set_get_crl(ctx: PX509_STORE; get_crl: X509_STORE_CTX_get_crl_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_get_crl');
end;

function ERROR_X509_STORE_get_get_crl(ctx: PX509_STORE): X509_STORE_CTX_get_crl_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_get_crl');
end;

procedure ERROR_X509_STORE_set_check_crl(ctx: PX509_STORE; check_crl: X509_STORE_CTX_check_crl_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_check_crl');
end;

function ERROR_X509_STORE_get_check_crl(ctx: PX509_STORE): X509_STORE_CTX_check_crl_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_check_crl');
end;

procedure ERROR_X509_STORE_set_cert_crl(ctx: PX509_STORE; cert_crl: X509_STORE_CTX_cert_crl_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_cert_crl');
end;

function ERROR_X509_STORE_get_cert_crl(ctx: PX509_STORE): X509_STORE_CTX_cert_crl_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_cert_crl');
end;

procedure ERROR_X509_STORE_set_check_policy(ctx: PX509_STORE; check_policy: X509_STORE_CTX_check_policy_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_check_policy');
end;

function ERROR_X509_STORE_get_check_policy(ctx: PX509_STORE): X509_STORE_CTX_check_policy_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_check_policy');
end;

procedure ERROR_X509_STORE_set_cleanup(ctx: PX509_STORE; cleanup: X509_STORE_CTX_cleanup_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_cleanup');
end;

function ERROR_X509_STORE_get_cleanup(ctx: PX509_STORE): X509_STORE_CTX_cleanup_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_cleanup');
end;

function ERROR_X509_STORE_set_ex_data(ctx: PX509_STORE; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_ex_data');
end;

function ERROR_X509_STORE_get_ex_data(ctx: PX509_STORE; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_get_ex_data');
end;

function ERROR_X509_STORE_CTX_new: PX509_STORE_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_new');
end;

function ERROR_X509_STORE_CTX_get1_issuer(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get1_issuer');
end;

procedure ERROR_X509_STORE_CTX_free(ctx: PX509_STORE_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_free');
end;

procedure ERROR_X509_STORE_CTX_cleanup(ctx: PX509_STORE_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_cleanup');
end;

function ERROR_X509_STORE_CTX_get0_store(ctx: PX509_STORE_CTX): PX509_STORE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get0_store');
end;

function ERROR_X509_STORE_CTX_get0_cert(ctx: PX509_STORE_CTX): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get0_cert');
end;

procedure ERROR_X509_STORE_CTX_set_verify_cb(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_verify_cb');
end;

function ERROR_X509_STORE_CTX_get_verify_cb(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_verify_cb');
end;

function ERROR_X509_STORE_CTX_get_verify(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_verify');
end;

function ERROR_X509_STORE_CTX_get_get_issuer(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_issuer_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_get_issuer');
end;

function ERROR_X509_STORE_CTX_get_check_issued(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_issued_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_check_issued');
end;

function ERROR_X509_STORE_CTX_get_check_revocation(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_revocation_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_check_revocation');
end;

function ERROR_X509_STORE_CTX_get_get_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_crl_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_get_crl');
end;

function ERROR_X509_STORE_CTX_get_check_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_crl_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_check_crl');
end;

function ERROR_X509_STORE_CTX_get_cert_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_cert_crl_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_cert_crl');
end;

function ERROR_X509_STORE_CTX_get_check_policy(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_policy_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_check_policy');
end;

function ERROR_X509_STORE_CTX_get_cleanup(ctx: PX509_STORE_CTX): X509_STORE_CTX_cleanup_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_cleanup');
end;

function ERROR_X509_STORE_add_lookup(v: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_add_lookup');
end;

function ERROR_X509_LOOKUP_hash_dir: PX509_LOOKUP_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_hash_dir');
end;

function ERROR_X509_LOOKUP_file: PX509_LOOKUP_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_file');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_LOOKUP_meth_new(const name: PAnsiChar): PX509_LOOKUP_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_new');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_set_ctrl');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_LOOKUP_meth_get_ctrl(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_ctrl_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_get_ctrl');
end;

function ERROR_X509_LOOKUP_meth_set_get_by_subject(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_subject_fn): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_set_get_by_subject');
end;

function ERROR_X509_LOOKUP_meth_get_get_by_subject(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_subject_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_get_get_by_subject');
end;

function ERROR_X509_LOOKUP_meth_set_get_by_issuer_serial(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_issuer_serial_fn): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_set_get_by_issuer_serial');
end;

function ERROR_X509_LOOKUP_meth_get_get_by_issuer_serial(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_issuer_serial_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_get_get_by_issuer_serial');
end;

function ERROR_X509_LOOKUP_meth_set_get_by_fingerprint(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_fingerprint_fn): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_set_get_by_fingerprint');
end;

function ERROR_X509_LOOKUP_meth_get_get_by_fingerprint(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_fingerprint_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_get_get_by_fingerprint');
end;

function ERROR_X509_LOOKUP_meth_set_get_by_alias(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_alias_fn): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_set_get_by_alias');
end;

function ERROR_X509_LOOKUP_meth_get_get_by_alias(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_alias_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_meth_get_get_by_alias');
end;

function ERROR_X509_STORE_add_cert(ctx: PX509_STORE; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_add_cert');
end;

function ERROR_X509_STORE_add_crl(ctx: PX509_STORE; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_add_crl');
end;

function ERROR_X509_STORE_CTX_get_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_by_subject');
end;

function ERROR_X509_STORE_CTX_get_obj_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_obj_by_subject');
end;

function ERROR_X509_LOOKUP_ctrl(ctx: PX509_LOOKUP; cmd: TOpenSSL_C_INT; const argc: PAnsiChar; argl: TOpenSSL_C_LONG; ret: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_ctrl');
end;

function ERROR_X509_load_cert_file(ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_load_cert_file');
end;

function ERROR_X509_load_crl_file(ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_load_crl_file');
end;

function ERROR_X509_load_cert_crl_file(ctx: PX509_LOOKUP; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_load_cert_crl_file');
end;

function ERROR_X509_LOOKUP_new(method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_new');
end;

procedure ERROR_X509_LOOKUP_free(ctx: PX509_LOOKUP); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_free');
end;

function ERROR_X509_LOOKUP_init(ctx: PX509_LOOKUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_init');
end;

function ERROR_X509_LOOKUP_by_subject(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_by_subject');
end;

function ERROR_X509_LOOKUP_by_issuer_serial(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_by_issuer_serial');
end;

function ERROR_X509_LOOKUP_by_fingerprint(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const bytes: PByte; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_by_fingerprint');
end;

function ERROR_X509_LOOKUP_by_alias(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const str: PAnsiChar; len: TOpenSSL_C_INT; ret: PX509_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_by_alias');
end;

function ERROR_X509_LOOKUP_set_method_data(ctx: PX509_LOOKUP; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_set_method_data');
end;

function ERROR_X509_LOOKUP_get_method_data(const ctx: PX509_LOOKUP): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_get_method_data');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_LOOKUP_get_store(const ctx: PX509_LOOKUP): PX509_STORE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_get_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_LOOKUP_shutdown(ctx: PX509_LOOKUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_LOOKUP_shutdown');
end;

function ERROR_X509_STORE_load_locations(ctx: PX509_STORE; const file_: PAnsiChar; const dir: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_load_locations');
end;

function ERROR_X509_STORE_set_default_paths(ctx: PX509_STORE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_set_default_paths');
end;

function ERROR_X509_STORE_CTX_set_ex_data(ctx: PX509_STORE_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_ex_data');
end;

function ERROR_X509_STORE_CTX_get_ex_data(ctx: PX509_STORE_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_ex_data');
end;

function ERROR_X509_STORE_CTX_get_error(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_error');
end;

procedure ERROR_X509_STORE_CTX_set_error(ctx: X509_STORE_CTX; s: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_error');
end;

function ERROR_X509_STORE_CTX_get_error_depth(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_error_depth');
end;

procedure ERROR_X509_STORE_CTX_set_error_depth(ctx: PX509_STORE_CTX; depth: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_error_depth');
end;

function ERROR_X509_STORE_CTX_get_current_cert(ctx: PX509_STORE_CTX): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_current_cert');
end;

procedure ERROR_X509_STORE_CTX_set_current_cert(ctx: PX509_STORE_CTX; x: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_current_cert');
end;

function ERROR_X509_STORE_CTX_get0_current_issuer(ctx: PX509_STORE_CTX): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get0_current_issuer');
end;

function ERROR_X509_STORE_CTX_get0_current_crl(ctx: PX509_STORE_CTX): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get0_current_crl');
end;

function ERROR_X509_STORE_CTX_get0_parent_ctx(ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get0_parent_ctx');
end;

procedure ERROR_X509_STORE_CTX_set_cert(c: PX509_STORE_CTX; x: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_cert');
end;

function ERROR_X509_STORE_CTX_set_purpose(ctx: PX509_STORE_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_purpose');
end;

function ERROR_X509_STORE_CTX_set_trust(ctx: PX509_STORE_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_trust');
end;

function ERROR_X509_STORE_CTX_purpose_inherit(ctx: PX509_STORE_CTX; def_purpose: TOpenSSL_C_INT; purpose: TOpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_purpose_inherit');
end;

procedure ERROR_X509_STORE_CTX_set_flags(ctx: PX509_STORE_CTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_flags');
end;

function ERROR_X509_STORE_CTX_get0_policy_tree(ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get0_policy_tree');
end;

function ERROR_X509_STORE_CTX_get_explicit_policy(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_explicit_policy');
end;

function ERROR_X509_STORE_CTX_get_num_untrusted(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get_num_untrusted');
end;

function ERROR_X509_STORE_CTX_get0_param(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_get0_param');
end;

procedure ERROR_X509_STORE_CTX_set0_param(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set0_param');
end;

function ERROR_X509_STORE_CTX_set_default(ctx: PX509_STORE_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set_default');
end;

procedure ERROR_X509_STORE_CTX_set0_dane(ctx: PX509_STORE_CTX; dane: PSSL_DANE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_STORE_CTX_set0_dane');
end;

function ERROR_X509_VERIFY_PARAM_new: PX509_VERIFY_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_new');
end;

procedure ERROR_X509_VERIFY_PARAM_free(param: PX509_VERIFY_PARAM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_free');
end;

function ERROR_X509_VERIFY_PARAM_inherit(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_inherit');
end;

function ERROR_X509_VERIFY_PARAM_set1(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set1');
end;

function ERROR_X509_VERIFY_PARAM_set1_name(param: PX509_VERIFY_PARAM; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set1_name');
end;

function ERROR_X509_VERIFY_PARAM_set_flags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set_flags');
end;

function ERROR_X509_VERIFY_PARAM_clear_flags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_clear_flags');
end;

function ERROR_X509_VERIFY_PARAM_get_flags(param: PX509_VERIFY_PARAM): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get_flags');
end;

function ERROR_X509_VERIFY_PARAM_set_purpose(param: PX509_VERIFY_PARAM; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set_purpose');
end;

function ERROR_X509_VERIFY_PARAM_set_trust(param: PX509_VERIFY_PARAM; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set_trust');
end;

procedure ERROR_X509_VERIFY_PARAM_set_depth(param: PX509_VERIFY_PARAM; depth: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set_depth');
end;

procedure ERROR_X509_VERIFY_PARAM_set_auth_level(param: PX509_VERIFY_PARAM; auth_level: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set_auth_level');
end;

function ERROR_X509_VERIFY_PARAM_add0_policy(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_add0_policy');
end;

function ERROR_X509_VERIFY_PARAM_set_inh_flags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set_inh_flags');
end;

function ERROR_X509_VERIFY_PARAM_get_inh_flags(const param: PX509_VERIFY_PARAM): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get_inh_flags');
end;

function ERROR_X509_VERIFY_PARAM_set1_host(param: PX509_VERIFY_PARAM; const name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set1_host');
end;

function ERROR_X509_VERIFY_PARAM_add1_host(param: PX509_VERIFY_PARAM; const name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_add1_host');
end;

procedure ERROR_X509_VERIFY_PARAM_set_hostflags(param: PX509_VERIFY_PARAM; flags: TOpenSSL_C_UINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set_hostflags');
end;

function ERROR_X509_VERIFY_PARAM_get_hostflags(const param: PX509_VERIFY_PARAM): TOpenSSL_C_UINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get_hostflags');
end;

function ERROR_X509_VERIFY_PARAM_get0_peername(v1: PX509_VERIFY_PARAM): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get0_peername');
end;

procedure ERROR_X509_VERIFY_PARAM_move_peername(v1: PX509_VERIFY_PARAM; v2: PX509_VERIFY_PARAM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_move_peername');
end;

function ERROR_X509_VERIFY_PARAM_set1_email(param: PX509_VERIFY_PARAM; const email: PAnsiChar; emaillen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set1_email');
end;

function ERROR_X509_VERIFY_PARAM_set1_ip(param: PX509_VERIFY_PARAM; const ip: PByte; iplen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set1_ip');
end;

function ERROR_X509_VERIFY_PARAM_set1_ip_asc(param: PX509_VERIFY_PARAM; const ipasc: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_set1_ip_asc');
end;

function ERROR_X509_VERIFY_PARAM_get_depth(const param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get_depth');
end;

function ERROR_X509_VERIFY_PARAM_get_auth_level(const param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get_auth_level');
end;

function ERROR_X509_VERIFY_PARAM_get0_name(const param: PX509_VERIFY_PARAM): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get0_name');
end;

function ERROR_X509_VERIFY_PARAM_add0_table(param: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_add0_table');
end;

function ERROR_X509_VERIFY_PARAM_get_count: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get_count');
end;

function ERROR_X509_VERIFY_PARAM_get0(id: TOpenSSL_C_INT): PX509_VERIFY_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_get0');
end;

function ERROR_X509_VERIFY_PARAM_lookup(const name: PAnsiChar): X509_VERIFY_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_lookup');
end;

procedure ERROR_X509_VERIFY_PARAM_table_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VERIFY_PARAM_table_cleanup');
end;

procedure ERROR_X509_policy_tree_free(tree: PX509_POLICY_TREE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_policy_tree_free');
end;

function ERROR_X509_policy_tree_level_count(const tree: PX509_POLICY_TREE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_policy_tree_level_count');
end;

function ERROR_X509_policy_tree_get0_level(const tree: PX509_POLICY_TREE; i: TOpenSSL_C_INT): PX509_POLICY_LEVEL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_policy_tree_get0_level');
end;

function ERROR_X509_policy_level_node_count(level: PX509_POLICY_LEVEL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_policy_level_node_count');
end;

function ERROR_X509_policy_level_get0_node(level: PX509_POLICY_LEVEL; i: TOpenSSL_C_INT): PX509_POLICY_NODE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_policy_level_get0_node');
end;

function ERROR_X509_policy_node_get0_policy(const node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_policy_node_get0_policy');
end;

function ERROR_X509_policy_node_get0_parent(const node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_policy_node_get0_parent');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$MINENUMSIZE 4}
  X509_STORE_set_depth := LoadLibCryptoFunction('X509_STORE_set_depth');
  FuncLoadError := not assigned(X509_STORE_set_depth);
  if FuncLoadError then
  begin
    X509_STORE_set_depth :=  @ERROR_X509_STORE_set_depth;
  end;

  X509_STORE_CTX_set_depth := LoadLibCryptoFunction('X509_STORE_CTX_set_depth');
  FuncLoadError := not assigned(X509_STORE_CTX_set_depth);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_depth :=  @ERROR_X509_STORE_CTX_set_depth;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_STORE_CTX_get_app_data := LoadLibCryptoFunction('X509_STORE_CTX_get_app_data');
  FuncLoadError := not assigned(X509_STORE_CTX_get_app_data);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_app_data := @COMPAT_X509_STORE_CTX_get_app_data;
    if X509_STORE_CTX_get_app_data_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_app_data');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_OBJECT_up_ref_count := LoadLibCryptoFunction('X509_OBJECT_up_ref_count');
  FuncLoadError := not assigned(X509_OBJECT_up_ref_count);
  if FuncLoadError then
  begin
    X509_OBJECT_up_ref_count :=  @ERROR_X509_OBJECT_up_ref_count;
  end;

  X509_OBJECT_new := LoadLibCryptoFunction('X509_OBJECT_new');
  FuncLoadError := not assigned(X509_OBJECT_new);
  if FuncLoadError then
  begin
    X509_OBJECT_new :=  @ERROR_X509_OBJECT_new;
  end;

  X509_OBJECT_free := LoadLibCryptoFunction('X509_OBJECT_free');
  FuncLoadError := not assigned(X509_OBJECT_free);
  if FuncLoadError then
  begin
    X509_OBJECT_free :=  @ERROR_X509_OBJECT_free;
  end;

  X509_OBJECT_get_type := LoadLibCryptoFunction('X509_OBJECT_get_type');
  FuncLoadError := not assigned(X509_OBJECT_get_type);
  if FuncLoadError then
  begin
    X509_OBJECT_get_type :=  @ERROR_X509_OBJECT_get_type;
  end;

  X509_OBJECT_get0_X509 := LoadLibCryptoFunction('X509_OBJECT_get0_X509');
  FuncLoadError := not assigned(X509_OBJECT_get0_X509);
  if FuncLoadError then
  begin
    X509_OBJECT_get0_X509 :=  @ERROR_X509_OBJECT_get0_X509;
  end;

  X509_OBJECT_set1_X509 := LoadLibCryptoFunction('X509_OBJECT_set1_X509');
  FuncLoadError := not assigned(X509_OBJECT_set1_X509);
  if FuncLoadError then
  begin
    X509_OBJECT_set1_X509 :=  @ERROR_X509_OBJECT_set1_X509;
  end;

  X509_OBJECT_get0_X509_CRL := LoadLibCryptoFunction('X509_OBJECT_get0_X509_CRL');
  FuncLoadError := not assigned(X509_OBJECT_get0_X509_CRL);
  if FuncLoadError then
  begin
    X509_OBJECT_get0_X509_CRL :=  @ERROR_X509_OBJECT_get0_X509_CRL;
  end;

  X509_OBJECT_set1_X509_CRL := LoadLibCryptoFunction('X509_OBJECT_set1_X509_CRL');
  FuncLoadError := not assigned(X509_OBJECT_set1_X509_CRL);
  if FuncLoadError then
  begin
    X509_OBJECT_set1_X509_CRL :=  @ERROR_X509_OBJECT_set1_X509_CRL;
  end;

  X509_STORE_new := LoadLibCryptoFunction('X509_STORE_new');
  FuncLoadError := not assigned(X509_STORE_new);
  if FuncLoadError then
  begin
    X509_STORE_new :=  @ERROR_X509_STORE_new;
  end;

  X509_STORE_free := LoadLibCryptoFunction('X509_STORE_free');
  FuncLoadError := not assigned(X509_STORE_free);
  if FuncLoadError then
  begin
    X509_STORE_free :=  @ERROR_X509_STORE_free;
  end;

  X509_STORE_lock := LoadLibCryptoFunction('X509_STORE_lock');
  FuncLoadError := not assigned(X509_STORE_lock);
  if FuncLoadError then
  begin
    X509_STORE_lock :=  @ERROR_X509_STORE_lock;
  end;

  X509_STORE_unlock := LoadLibCryptoFunction('X509_STORE_unlock');
  FuncLoadError := not assigned(X509_STORE_unlock);
  if FuncLoadError then
  begin
    X509_STORE_unlock :=  @ERROR_X509_STORE_unlock;
  end;

  X509_STORE_up_ref := LoadLibCryptoFunction('X509_STORE_up_ref');
  FuncLoadError := not assigned(X509_STORE_up_ref);
  if FuncLoadError then
  begin
    X509_STORE_up_ref :=  @ERROR_X509_STORE_up_ref;
  end;

  X509_STORE_set_flags := LoadLibCryptoFunction('X509_STORE_set_flags');
  FuncLoadError := not assigned(X509_STORE_set_flags);
  if FuncLoadError then
  begin
    X509_STORE_set_flags :=  @ERROR_X509_STORE_set_flags;
  end;

  X509_STORE_set_purpose := LoadLibCryptoFunction('X509_STORE_set_purpose');
  FuncLoadError := not assigned(X509_STORE_set_purpose);
  if FuncLoadError then
  begin
    X509_STORE_set_purpose :=  @ERROR_X509_STORE_set_purpose;
  end;

  X509_STORE_set_trust := LoadLibCryptoFunction('X509_STORE_set_trust');
  FuncLoadError := not assigned(X509_STORE_set_trust);
  if FuncLoadError then
  begin
    X509_STORE_set_trust :=  @ERROR_X509_STORE_set_trust;
  end;

  X509_STORE_set1_param := LoadLibCryptoFunction('X509_STORE_set1_param');
  FuncLoadError := not assigned(X509_STORE_set1_param);
  if FuncLoadError then
  begin
    X509_STORE_set1_param :=  @ERROR_X509_STORE_set1_param;
  end;

  X509_STORE_get0_param := LoadLibCryptoFunction('X509_STORE_get0_param');
  FuncLoadError := not assigned(X509_STORE_get0_param);
  if FuncLoadError then
  begin
    X509_STORE_get0_param :=  @ERROR_X509_STORE_get0_param;
  end;

  X509_STORE_set_verify := LoadLibCryptoFunction('X509_STORE_set_verify');
  FuncLoadError := not assigned(X509_STORE_set_verify);
  if FuncLoadError then
  begin
    X509_STORE_set_verify :=  @ERROR_X509_STORE_set_verify;
  end;

  X509_STORE_CTX_set_verify := LoadLibCryptoFunction('X509_STORE_CTX_set_verify');
  FuncLoadError := not assigned(X509_STORE_CTX_set_verify);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_verify :=  @ERROR_X509_STORE_CTX_set_verify;
  end;

  X509_STORE_get_verify := LoadLibCryptoFunction('X509_STORE_get_verify');
  FuncLoadError := not assigned(X509_STORE_get_verify);
  if FuncLoadError then
  begin
    X509_STORE_get_verify :=  @ERROR_X509_STORE_get_verify;
  end;

  X509_STORE_set_verify_cb := LoadLibCryptoFunction('X509_STORE_set_verify_cb');
  FuncLoadError := not assigned(X509_STORE_set_verify_cb);
  if FuncLoadError then
  begin
    X509_STORE_set_verify_cb :=  @ERROR_X509_STORE_set_verify_cb;
  end;

  X509_STORE_get_verify_cb := LoadLibCryptoFunction('X509_STORE_get_verify_cb');
  FuncLoadError := not assigned(X509_STORE_get_verify_cb);
  if FuncLoadError then
  begin
    X509_STORE_get_verify_cb :=  @ERROR_X509_STORE_get_verify_cb;
  end;

  X509_STORE_set_get_issuer := LoadLibCryptoFunction('X509_STORE_set_get_issuer');
  FuncLoadError := not assigned(X509_STORE_set_get_issuer);
  if FuncLoadError then
  begin
    X509_STORE_set_get_issuer :=  @ERROR_X509_STORE_set_get_issuer;
  end;

  X509_STORE_get_get_issuer := LoadLibCryptoFunction('X509_STORE_get_get_issuer');
  FuncLoadError := not assigned(X509_STORE_get_get_issuer);
  if FuncLoadError then
  begin
    X509_STORE_get_get_issuer :=  @ERROR_X509_STORE_get_get_issuer;
  end;

  X509_STORE_set_check_issued := LoadLibCryptoFunction('X509_STORE_set_check_issued');
  FuncLoadError := not assigned(X509_STORE_set_check_issued);
  if FuncLoadError then
  begin
    X509_STORE_set_check_issued :=  @ERROR_X509_STORE_set_check_issued;
  end;

  X509_STORE_get_check_issued := LoadLibCryptoFunction('X509_STORE_get_check_issued');
  FuncLoadError := not assigned(X509_STORE_get_check_issued);
  if FuncLoadError then
  begin
    X509_STORE_get_check_issued :=  @ERROR_X509_STORE_get_check_issued;
  end;

  X509_STORE_set_check_revocation := LoadLibCryptoFunction('X509_STORE_set_check_revocation');
  FuncLoadError := not assigned(X509_STORE_set_check_revocation);
  if FuncLoadError then
  begin
    X509_STORE_set_check_revocation :=  @ERROR_X509_STORE_set_check_revocation;
  end;

  X509_STORE_get_check_revocation := LoadLibCryptoFunction('X509_STORE_get_check_revocation');
  FuncLoadError := not assigned(X509_STORE_get_check_revocation);
  if FuncLoadError then
  begin
    X509_STORE_get_check_revocation :=  @ERROR_X509_STORE_get_check_revocation;
  end;

  X509_STORE_set_get_crl := LoadLibCryptoFunction('X509_STORE_set_get_crl');
  FuncLoadError := not assigned(X509_STORE_set_get_crl);
  if FuncLoadError then
  begin
    X509_STORE_set_get_crl :=  @ERROR_X509_STORE_set_get_crl;
  end;

  X509_STORE_get_get_crl := LoadLibCryptoFunction('X509_STORE_get_get_crl');
  FuncLoadError := not assigned(X509_STORE_get_get_crl);
  if FuncLoadError then
  begin
    X509_STORE_get_get_crl :=  @ERROR_X509_STORE_get_get_crl;
  end;

  X509_STORE_set_check_crl := LoadLibCryptoFunction('X509_STORE_set_check_crl');
  FuncLoadError := not assigned(X509_STORE_set_check_crl);
  if FuncLoadError then
  begin
    X509_STORE_set_check_crl :=  @ERROR_X509_STORE_set_check_crl;
  end;

  X509_STORE_get_check_crl := LoadLibCryptoFunction('X509_STORE_get_check_crl');
  FuncLoadError := not assigned(X509_STORE_get_check_crl);
  if FuncLoadError then
  begin
    X509_STORE_get_check_crl :=  @ERROR_X509_STORE_get_check_crl;
  end;

  X509_STORE_set_cert_crl := LoadLibCryptoFunction('X509_STORE_set_cert_crl');
  FuncLoadError := not assigned(X509_STORE_set_cert_crl);
  if FuncLoadError then
  begin
    X509_STORE_set_cert_crl :=  @ERROR_X509_STORE_set_cert_crl;
  end;

  X509_STORE_get_cert_crl := LoadLibCryptoFunction('X509_STORE_get_cert_crl');
  FuncLoadError := not assigned(X509_STORE_get_cert_crl);
  if FuncLoadError then
  begin
    X509_STORE_get_cert_crl :=  @ERROR_X509_STORE_get_cert_crl;
  end;

  X509_STORE_set_check_policy := LoadLibCryptoFunction('X509_STORE_set_check_policy');
  FuncLoadError := not assigned(X509_STORE_set_check_policy);
  if FuncLoadError then
  begin
    X509_STORE_set_check_policy :=  @ERROR_X509_STORE_set_check_policy;
  end;

  X509_STORE_get_check_policy := LoadLibCryptoFunction('X509_STORE_get_check_policy');
  FuncLoadError := not assigned(X509_STORE_get_check_policy);
  if FuncLoadError then
  begin
    X509_STORE_get_check_policy :=  @ERROR_X509_STORE_get_check_policy;
  end;

  X509_STORE_set_cleanup := LoadLibCryptoFunction('X509_STORE_set_cleanup');
  FuncLoadError := not assigned(X509_STORE_set_cleanup);
  if FuncLoadError then
  begin
    X509_STORE_set_cleanup :=  @ERROR_X509_STORE_set_cleanup;
  end;

  X509_STORE_get_cleanup := LoadLibCryptoFunction('X509_STORE_get_cleanup');
  FuncLoadError := not assigned(X509_STORE_get_cleanup);
  if FuncLoadError then
  begin
    X509_STORE_get_cleanup :=  @ERROR_X509_STORE_get_cleanup;
  end;

  X509_STORE_set_ex_data := LoadLibCryptoFunction('X509_STORE_set_ex_data');
  FuncLoadError := not assigned(X509_STORE_set_ex_data);
  if FuncLoadError then
  begin
    X509_STORE_set_ex_data :=  @ERROR_X509_STORE_set_ex_data;
  end;

  X509_STORE_get_ex_data := LoadLibCryptoFunction('X509_STORE_get_ex_data');
  FuncLoadError := not assigned(X509_STORE_get_ex_data);
  if FuncLoadError then
  begin
    X509_STORE_get_ex_data :=  @ERROR_X509_STORE_get_ex_data;
  end;

  X509_STORE_CTX_new := LoadLibCryptoFunction('X509_STORE_CTX_new');
  FuncLoadError := not assigned(X509_STORE_CTX_new);
  if FuncLoadError then
  begin
    X509_STORE_CTX_new :=  @ERROR_X509_STORE_CTX_new;
  end;

  X509_STORE_CTX_get1_issuer := LoadLibCryptoFunction('X509_STORE_CTX_get1_issuer');
  FuncLoadError := not assigned(X509_STORE_CTX_get1_issuer);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get1_issuer :=  @ERROR_X509_STORE_CTX_get1_issuer;
  end;

  X509_STORE_CTX_free := LoadLibCryptoFunction('X509_STORE_CTX_free');
  FuncLoadError := not assigned(X509_STORE_CTX_free);
  if FuncLoadError then
  begin
    X509_STORE_CTX_free :=  @ERROR_X509_STORE_CTX_free;
  end;

  X509_STORE_CTX_cleanup := LoadLibCryptoFunction('X509_STORE_CTX_cleanup');
  FuncLoadError := not assigned(X509_STORE_CTX_cleanup);
  if FuncLoadError then
  begin
    X509_STORE_CTX_cleanup :=  @ERROR_X509_STORE_CTX_cleanup;
  end;

  X509_STORE_CTX_get0_store := LoadLibCryptoFunction('X509_STORE_CTX_get0_store');
  FuncLoadError := not assigned(X509_STORE_CTX_get0_store);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get0_store :=  @ERROR_X509_STORE_CTX_get0_store;
  end;

  X509_STORE_CTX_get0_cert := LoadLibCryptoFunction('X509_STORE_CTX_get0_cert');
  FuncLoadError := not assigned(X509_STORE_CTX_get0_cert);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get0_cert :=  @ERROR_X509_STORE_CTX_get0_cert;
  end;

  X509_STORE_CTX_set_verify_cb := LoadLibCryptoFunction('X509_STORE_CTX_set_verify_cb');
  FuncLoadError := not assigned(X509_STORE_CTX_set_verify_cb);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_verify_cb :=  @ERROR_X509_STORE_CTX_set_verify_cb;
  end;

  X509_STORE_CTX_get_verify_cb := LoadLibCryptoFunction('X509_STORE_CTX_get_verify_cb');
  FuncLoadError := not assigned(X509_STORE_CTX_get_verify_cb);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_verify_cb :=  @ERROR_X509_STORE_CTX_get_verify_cb;
  end;

  X509_STORE_CTX_get_verify := LoadLibCryptoFunction('X509_STORE_CTX_get_verify');
  FuncLoadError := not assigned(X509_STORE_CTX_get_verify);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_verify :=  @ERROR_X509_STORE_CTX_get_verify;
  end;

  X509_STORE_CTX_get_get_issuer := LoadLibCryptoFunction('X509_STORE_CTX_get_get_issuer');
  FuncLoadError := not assigned(X509_STORE_CTX_get_get_issuer);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_get_issuer :=  @ERROR_X509_STORE_CTX_get_get_issuer;
  end;

  X509_STORE_CTX_get_check_issued := LoadLibCryptoFunction('X509_STORE_CTX_get_check_issued');
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_issued);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_check_issued :=  @ERROR_X509_STORE_CTX_get_check_issued;
  end;

  X509_STORE_CTX_get_check_revocation := LoadLibCryptoFunction('X509_STORE_CTX_get_check_revocation');
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_revocation);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_check_revocation :=  @ERROR_X509_STORE_CTX_get_check_revocation;
  end;

  X509_STORE_CTX_get_get_crl := LoadLibCryptoFunction('X509_STORE_CTX_get_get_crl');
  FuncLoadError := not assigned(X509_STORE_CTX_get_get_crl);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_get_crl :=  @ERROR_X509_STORE_CTX_get_get_crl;
  end;

  X509_STORE_CTX_get_check_crl := LoadLibCryptoFunction('X509_STORE_CTX_get_check_crl');
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_crl);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_check_crl :=  @ERROR_X509_STORE_CTX_get_check_crl;
  end;

  X509_STORE_CTX_get_cert_crl := LoadLibCryptoFunction('X509_STORE_CTX_get_cert_crl');
  FuncLoadError := not assigned(X509_STORE_CTX_get_cert_crl);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_cert_crl :=  @ERROR_X509_STORE_CTX_get_cert_crl;
  end;

  X509_STORE_CTX_get_check_policy := LoadLibCryptoFunction('X509_STORE_CTX_get_check_policy');
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_policy);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_check_policy :=  @ERROR_X509_STORE_CTX_get_check_policy;
  end;

  X509_STORE_CTX_get_cleanup := LoadLibCryptoFunction('X509_STORE_CTX_get_cleanup');
  FuncLoadError := not assigned(X509_STORE_CTX_get_cleanup);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_cleanup :=  @ERROR_X509_STORE_CTX_get_cleanup;
  end;

  X509_STORE_add_lookup := LoadLibCryptoFunction('X509_STORE_add_lookup');
  FuncLoadError := not assigned(X509_STORE_add_lookup);
  if FuncLoadError then
  begin
    X509_STORE_add_lookup :=  @ERROR_X509_STORE_add_lookup;
  end;

  X509_LOOKUP_hash_dir := LoadLibCryptoFunction('X509_LOOKUP_hash_dir');
  FuncLoadError := not assigned(X509_LOOKUP_hash_dir);
  if FuncLoadError then
  begin
    X509_LOOKUP_hash_dir :=  @ERROR_X509_LOOKUP_hash_dir;
  end;

  X509_LOOKUP_file := LoadLibCryptoFunction('X509_LOOKUP_file');
  FuncLoadError := not assigned(X509_LOOKUP_file);
  if FuncLoadError then
  begin
    X509_LOOKUP_file :=  @ERROR_X509_LOOKUP_file;
  end;

  X509_LOOKUP_meth_new := LoadLibCryptoFunction('X509_LOOKUP_meth_new');
  FuncLoadError := not assigned(X509_LOOKUP_meth_new);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_LOOKUP_meth_new := @COMPAT_X509_LOOKUP_meth_new;
{$ELSE}
    X509_LOOKUP_meth_new :=  @ERROR_X509_LOOKUP_meth_new;
{$ENDIF}
  end;

  X509_LOOKUP_meth_free := LoadLibCryptoFunction('X509_LOOKUP_meth_free');
  FuncLoadError := not assigned(X509_LOOKUP_meth_free);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_LOOKUP_meth_free := @COMPAT_X509_LOOKUP_meth_free;
{$ELSE}
    X509_LOOKUP_meth_free :=  @ERROR_X509_LOOKUP_meth_free;
{$ENDIF}
  end;

  X509_LOOKUP_meth_set_ctrl := LoadLibCryptoFunction('X509_LOOKUP_meth_set_ctrl');
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_ctrl);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_LOOKUP_meth_set_ctrl := @COMPAT_X509_LOOKUP_meth_set_ctrl;
{$ELSE}
    X509_LOOKUP_meth_set_ctrl :=  @ERROR_X509_LOOKUP_meth_set_ctrl;
{$ENDIF}
  end;

  X509_LOOKUP_meth_get_ctrl := LoadLibCryptoFunction('X509_LOOKUP_meth_get_ctrl');
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_ctrl);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_get_ctrl :=  @ERROR_X509_LOOKUP_meth_get_ctrl;
  end;

  X509_LOOKUP_meth_set_get_by_subject := LoadLibCryptoFunction('X509_LOOKUP_meth_set_get_by_subject');
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_subject);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_set_get_by_subject :=  @ERROR_X509_LOOKUP_meth_set_get_by_subject;
  end;

  X509_LOOKUP_meth_get_get_by_subject := LoadLibCryptoFunction('X509_LOOKUP_meth_get_get_by_subject');
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_subject);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_get_get_by_subject :=  @ERROR_X509_LOOKUP_meth_get_get_by_subject;
  end;

  X509_LOOKUP_meth_set_get_by_issuer_serial := LoadLibCryptoFunction('X509_LOOKUP_meth_set_get_by_issuer_serial');
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_issuer_serial);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_set_get_by_issuer_serial :=  @ERROR_X509_LOOKUP_meth_set_get_by_issuer_serial;
  end;

  X509_LOOKUP_meth_get_get_by_issuer_serial := LoadLibCryptoFunction('X509_LOOKUP_meth_get_get_by_issuer_serial');
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_issuer_serial);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_get_get_by_issuer_serial :=  @ERROR_X509_LOOKUP_meth_get_get_by_issuer_serial;
  end;

  X509_LOOKUP_meth_set_get_by_fingerprint := LoadLibCryptoFunction('X509_LOOKUP_meth_set_get_by_fingerprint');
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_fingerprint);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_set_get_by_fingerprint :=  @ERROR_X509_LOOKUP_meth_set_get_by_fingerprint;
  end;

  X509_LOOKUP_meth_get_get_by_fingerprint := LoadLibCryptoFunction('X509_LOOKUP_meth_get_get_by_fingerprint');
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_fingerprint);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_get_get_by_fingerprint :=  @ERROR_X509_LOOKUP_meth_get_get_by_fingerprint;
  end;

  X509_LOOKUP_meth_set_get_by_alias := LoadLibCryptoFunction('X509_LOOKUP_meth_set_get_by_alias');
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_alias);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_set_get_by_alias :=  @ERROR_X509_LOOKUP_meth_set_get_by_alias;
  end;

  X509_LOOKUP_meth_get_get_by_alias := LoadLibCryptoFunction('X509_LOOKUP_meth_get_get_by_alias');
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_alias);
  if FuncLoadError then
  begin
    X509_LOOKUP_meth_get_get_by_alias :=  @ERROR_X509_LOOKUP_meth_get_get_by_alias;
  end;

  X509_STORE_add_cert := LoadLibCryptoFunction('X509_STORE_add_cert');
  FuncLoadError := not assigned(X509_STORE_add_cert);
  if FuncLoadError then
  begin
    X509_STORE_add_cert :=  @ERROR_X509_STORE_add_cert;
  end;

  X509_STORE_add_crl := LoadLibCryptoFunction('X509_STORE_add_crl');
  FuncLoadError := not assigned(X509_STORE_add_crl);
  if FuncLoadError then
  begin
    X509_STORE_add_crl :=  @ERROR_X509_STORE_add_crl;
  end;

  X509_STORE_CTX_get_by_subject := LoadLibCryptoFunction('X509_STORE_CTX_get_by_subject');
  FuncLoadError := not assigned(X509_STORE_CTX_get_by_subject);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_by_subject :=  @ERROR_X509_STORE_CTX_get_by_subject;
  end;

  X509_STORE_CTX_get_obj_by_subject := LoadLibCryptoFunction('X509_STORE_CTX_get_obj_by_subject');
  FuncLoadError := not assigned(X509_STORE_CTX_get_obj_by_subject);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_obj_by_subject :=  @ERROR_X509_STORE_CTX_get_obj_by_subject;
  end;

  X509_LOOKUP_ctrl := LoadLibCryptoFunction('X509_LOOKUP_ctrl');
  FuncLoadError := not assigned(X509_LOOKUP_ctrl);
  if FuncLoadError then
  begin
    X509_LOOKUP_ctrl :=  @ERROR_X509_LOOKUP_ctrl;
  end;

  X509_load_cert_file := LoadLibCryptoFunction('X509_load_cert_file');
  FuncLoadError := not assigned(X509_load_cert_file);
  if FuncLoadError then
  begin
    X509_load_cert_file :=  @ERROR_X509_load_cert_file;
  end;

  X509_load_crl_file := LoadLibCryptoFunction('X509_load_crl_file');
  FuncLoadError := not assigned(X509_load_crl_file);
  if FuncLoadError then
  begin
    X509_load_crl_file :=  @ERROR_X509_load_crl_file;
  end;

  X509_load_cert_crl_file := LoadLibCryptoFunction('X509_load_cert_crl_file');
  FuncLoadError := not assigned(X509_load_cert_crl_file);
  if FuncLoadError then
  begin
    X509_load_cert_crl_file :=  @ERROR_X509_load_cert_crl_file;
  end;

  X509_LOOKUP_new := LoadLibCryptoFunction('X509_LOOKUP_new');
  FuncLoadError := not assigned(X509_LOOKUP_new);
  if FuncLoadError then
  begin
    X509_LOOKUP_new :=  @ERROR_X509_LOOKUP_new;
  end;

  X509_LOOKUP_free := LoadLibCryptoFunction('X509_LOOKUP_free');
  FuncLoadError := not assigned(X509_LOOKUP_free);
  if FuncLoadError then
  begin
    X509_LOOKUP_free :=  @ERROR_X509_LOOKUP_free;
  end;

  X509_LOOKUP_init := LoadLibCryptoFunction('X509_LOOKUP_init');
  FuncLoadError := not assigned(X509_LOOKUP_init);
  if FuncLoadError then
  begin
    X509_LOOKUP_init :=  @ERROR_X509_LOOKUP_init;
  end;

  X509_LOOKUP_by_subject := LoadLibCryptoFunction('X509_LOOKUP_by_subject');
  FuncLoadError := not assigned(X509_LOOKUP_by_subject);
  if FuncLoadError then
  begin
    X509_LOOKUP_by_subject :=  @ERROR_X509_LOOKUP_by_subject;
  end;

  X509_LOOKUP_by_issuer_serial := LoadLibCryptoFunction('X509_LOOKUP_by_issuer_serial');
  FuncLoadError := not assigned(X509_LOOKUP_by_issuer_serial);
  if FuncLoadError then
  begin
    X509_LOOKUP_by_issuer_serial :=  @ERROR_X509_LOOKUP_by_issuer_serial;
  end;

  X509_LOOKUP_by_fingerprint := LoadLibCryptoFunction('X509_LOOKUP_by_fingerprint');
  FuncLoadError := not assigned(X509_LOOKUP_by_fingerprint);
  if FuncLoadError then
  begin
    X509_LOOKUP_by_fingerprint :=  @ERROR_X509_LOOKUP_by_fingerprint;
  end;

  X509_LOOKUP_by_alias := LoadLibCryptoFunction('X509_LOOKUP_by_alias');
  FuncLoadError := not assigned(X509_LOOKUP_by_alias);
  if FuncLoadError then
  begin
    X509_LOOKUP_by_alias :=  @ERROR_X509_LOOKUP_by_alias;
  end;

  X509_LOOKUP_set_method_data := LoadLibCryptoFunction('X509_LOOKUP_set_method_data');
  FuncLoadError := not assigned(X509_LOOKUP_set_method_data);
  if FuncLoadError then
  begin
    X509_LOOKUP_set_method_data :=  @ERROR_X509_LOOKUP_set_method_data;
  end;

  X509_LOOKUP_get_method_data := LoadLibCryptoFunction('X509_LOOKUP_get_method_data');
  FuncLoadError := not assigned(X509_LOOKUP_get_method_data);
  if FuncLoadError then
  begin
    X509_LOOKUP_get_method_data :=  @ERROR_X509_LOOKUP_get_method_data;
  end;

  X509_LOOKUP_get_store := LoadLibCryptoFunction('X509_LOOKUP_get_store');
  FuncLoadError := not assigned(X509_LOOKUP_get_store);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_LOOKUP_get_store := @COMPAT_X509_LOOKUP_get_store;
{$ELSE}
    X509_LOOKUP_get_store :=  @ERROR_X509_LOOKUP_get_store;
{$ENDIF}
  end;

  X509_LOOKUP_shutdown := LoadLibCryptoFunction('X509_LOOKUP_shutdown');
  FuncLoadError := not assigned(X509_LOOKUP_shutdown);
  if FuncLoadError then
  begin
    X509_LOOKUP_shutdown :=  @ERROR_X509_LOOKUP_shutdown;
  end;

  X509_STORE_load_locations := LoadLibCryptoFunction('X509_STORE_load_locations');
  FuncLoadError := not assigned(X509_STORE_load_locations);
  if FuncLoadError then
  begin
    X509_STORE_load_locations :=  @ERROR_X509_STORE_load_locations;
  end;

  X509_STORE_set_default_paths := LoadLibCryptoFunction('X509_STORE_set_default_paths');
  FuncLoadError := not assigned(X509_STORE_set_default_paths);
  if FuncLoadError then
  begin
    X509_STORE_set_default_paths :=  @ERROR_X509_STORE_set_default_paths;
  end;

  X509_STORE_CTX_set_ex_data := LoadLibCryptoFunction('X509_STORE_CTX_set_ex_data');
  FuncLoadError := not assigned(X509_STORE_CTX_set_ex_data);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_ex_data :=  @ERROR_X509_STORE_CTX_set_ex_data;
  end;

  X509_STORE_CTX_get_ex_data := LoadLibCryptoFunction('X509_STORE_CTX_get_ex_data');
  FuncLoadError := not assigned(X509_STORE_CTX_get_ex_data);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_ex_data :=  @ERROR_X509_STORE_CTX_get_ex_data;
  end;

  X509_STORE_CTX_get_error := LoadLibCryptoFunction('X509_STORE_CTX_get_error');
  FuncLoadError := not assigned(X509_STORE_CTX_get_error);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_error :=  @ERROR_X509_STORE_CTX_get_error;
  end;

  X509_STORE_CTX_set_error := LoadLibCryptoFunction('X509_STORE_CTX_set_error');
  FuncLoadError := not assigned(X509_STORE_CTX_set_error);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_error :=  @ERROR_X509_STORE_CTX_set_error;
  end;

  X509_STORE_CTX_get_error_depth := LoadLibCryptoFunction('X509_STORE_CTX_get_error_depth');
  FuncLoadError := not assigned(X509_STORE_CTX_get_error_depth);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_error_depth :=  @ERROR_X509_STORE_CTX_get_error_depth;
  end;

  X509_STORE_CTX_set_error_depth := LoadLibCryptoFunction('X509_STORE_CTX_set_error_depth');
  FuncLoadError := not assigned(X509_STORE_CTX_set_error_depth);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_error_depth :=  @ERROR_X509_STORE_CTX_set_error_depth;
  end;

  X509_STORE_CTX_get_current_cert := LoadLibCryptoFunction('X509_STORE_CTX_get_current_cert');
  FuncLoadError := not assigned(X509_STORE_CTX_get_current_cert);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_current_cert :=  @ERROR_X509_STORE_CTX_get_current_cert;
  end;

  X509_STORE_CTX_set_current_cert := LoadLibCryptoFunction('X509_STORE_CTX_set_current_cert');
  FuncLoadError := not assigned(X509_STORE_CTX_set_current_cert);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_current_cert :=  @ERROR_X509_STORE_CTX_set_current_cert;
  end;

  X509_STORE_CTX_get0_current_issuer := LoadLibCryptoFunction('X509_STORE_CTX_get0_current_issuer');
  FuncLoadError := not assigned(X509_STORE_CTX_get0_current_issuer);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get0_current_issuer :=  @ERROR_X509_STORE_CTX_get0_current_issuer;
  end;

  X509_STORE_CTX_get0_current_crl := LoadLibCryptoFunction('X509_STORE_CTX_get0_current_crl');
  FuncLoadError := not assigned(X509_STORE_CTX_get0_current_crl);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get0_current_crl :=  @ERROR_X509_STORE_CTX_get0_current_crl;
  end;

  X509_STORE_CTX_get0_parent_ctx := LoadLibCryptoFunction('X509_STORE_CTX_get0_parent_ctx');
  FuncLoadError := not assigned(X509_STORE_CTX_get0_parent_ctx);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get0_parent_ctx :=  @ERROR_X509_STORE_CTX_get0_parent_ctx;
  end;

  X509_STORE_CTX_set_cert := LoadLibCryptoFunction('X509_STORE_CTX_set_cert');
  FuncLoadError := not assigned(X509_STORE_CTX_set_cert);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_cert :=  @ERROR_X509_STORE_CTX_set_cert;
  end;

  X509_STORE_CTX_set_purpose := LoadLibCryptoFunction('X509_STORE_CTX_set_purpose');
  FuncLoadError := not assigned(X509_STORE_CTX_set_purpose);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_purpose :=  @ERROR_X509_STORE_CTX_set_purpose;
  end;

  X509_STORE_CTX_set_trust := LoadLibCryptoFunction('X509_STORE_CTX_set_trust');
  FuncLoadError := not assigned(X509_STORE_CTX_set_trust);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_trust :=  @ERROR_X509_STORE_CTX_set_trust;
  end;

  X509_STORE_CTX_purpose_inherit := LoadLibCryptoFunction('X509_STORE_CTX_purpose_inherit');
  FuncLoadError := not assigned(X509_STORE_CTX_purpose_inherit);
  if FuncLoadError then
  begin
    X509_STORE_CTX_purpose_inherit :=  @ERROR_X509_STORE_CTX_purpose_inherit;
  end;

  X509_STORE_CTX_set_flags := LoadLibCryptoFunction('X509_STORE_CTX_set_flags');
  FuncLoadError := not assigned(X509_STORE_CTX_set_flags);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_flags :=  @ERROR_X509_STORE_CTX_set_flags;
  end;

  X509_STORE_CTX_get0_policy_tree := LoadLibCryptoFunction('X509_STORE_CTX_get0_policy_tree');
  FuncLoadError := not assigned(X509_STORE_CTX_get0_policy_tree);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get0_policy_tree :=  @ERROR_X509_STORE_CTX_get0_policy_tree;
  end;

  X509_STORE_CTX_get_explicit_policy := LoadLibCryptoFunction('X509_STORE_CTX_get_explicit_policy');
  FuncLoadError := not assigned(X509_STORE_CTX_get_explicit_policy);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_explicit_policy :=  @ERROR_X509_STORE_CTX_get_explicit_policy;
  end;

  X509_STORE_CTX_get_num_untrusted := LoadLibCryptoFunction('X509_STORE_CTX_get_num_untrusted');
  FuncLoadError := not assigned(X509_STORE_CTX_get_num_untrusted);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get_num_untrusted :=  @ERROR_X509_STORE_CTX_get_num_untrusted;
  end;

  X509_STORE_CTX_get0_param := LoadLibCryptoFunction('X509_STORE_CTX_get0_param');
  FuncLoadError := not assigned(X509_STORE_CTX_get0_param);
  if FuncLoadError then
  begin
    X509_STORE_CTX_get0_param :=  @ERROR_X509_STORE_CTX_get0_param;
  end;

  X509_STORE_CTX_set0_param := LoadLibCryptoFunction('X509_STORE_CTX_set0_param');
  FuncLoadError := not assigned(X509_STORE_CTX_set0_param);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set0_param :=  @ERROR_X509_STORE_CTX_set0_param;
  end;

  X509_STORE_CTX_set_default := LoadLibCryptoFunction('X509_STORE_CTX_set_default');
  FuncLoadError := not assigned(X509_STORE_CTX_set_default);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set_default :=  @ERROR_X509_STORE_CTX_set_default;
  end;

  X509_STORE_CTX_set0_dane := LoadLibCryptoFunction('X509_STORE_CTX_set0_dane');
  FuncLoadError := not assigned(X509_STORE_CTX_set0_dane);
  if FuncLoadError then
  begin
    X509_STORE_CTX_set0_dane :=  @ERROR_X509_STORE_CTX_set0_dane;
  end;

  X509_VERIFY_PARAM_new := LoadLibCryptoFunction('X509_VERIFY_PARAM_new');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_new);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_new :=  @ERROR_X509_VERIFY_PARAM_new;
  end;

  X509_VERIFY_PARAM_free := LoadLibCryptoFunction('X509_VERIFY_PARAM_free');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_free);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_free :=  @ERROR_X509_VERIFY_PARAM_free;
  end;

  X509_VERIFY_PARAM_inherit := LoadLibCryptoFunction('X509_VERIFY_PARAM_inherit');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_inherit);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_inherit :=  @ERROR_X509_VERIFY_PARAM_inherit;
  end;

  X509_VERIFY_PARAM_set1 := LoadLibCryptoFunction('X509_VERIFY_PARAM_set1');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set1 :=  @ERROR_X509_VERIFY_PARAM_set1;
  end;

  X509_VERIFY_PARAM_set1_name := LoadLibCryptoFunction('X509_VERIFY_PARAM_set1_name');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_name);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set1_name :=  @ERROR_X509_VERIFY_PARAM_set1_name;
  end;

  X509_VERIFY_PARAM_set_flags := LoadLibCryptoFunction('X509_VERIFY_PARAM_set_flags');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_flags);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set_flags :=  @ERROR_X509_VERIFY_PARAM_set_flags;
  end;

  X509_VERIFY_PARAM_clear_flags := LoadLibCryptoFunction('X509_VERIFY_PARAM_clear_flags');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_clear_flags);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_clear_flags :=  @ERROR_X509_VERIFY_PARAM_clear_flags;
  end;

  X509_VERIFY_PARAM_get_flags := LoadLibCryptoFunction('X509_VERIFY_PARAM_get_flags');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_flags);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get_flags :=  @ERROR_X509_VERIFY_PARAM_get_flags;
  end;

  X509_VERIFY_PARAM_set_purpose := LoadLibCryptoFunction('X509_VERIFY_PARAM_set_purpose');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_purpose);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set_purpose :=  @ERROR_X509_VERIFY_PARAM_set_purpose;
  end;

  X509_VERIFY_PARAM_set_trust := LoadLibCryptoFunction('X509_VERIFY_PARAM_set_trust');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_trust);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set_trust :=  @ERROR_X509_VERIFY_PARAM_set_trust;
  end;

  X509_VERIFY_PARAM_set_depth := LoadLibCryptoFunction('X509_VERIFY_PARAM_set_depth');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_depth);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set_depth :=  @ERROR_X509_VERIFY_PARAM_set_depth;
  end;

  X509_VERIFY_PARAM_set_auth_level := LoadLibCryptoFunction('X509_VERIFY_PARAM_set_auth_level');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_auth_level);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set_auth_level :=  @ERROR_X509_VERIFY_PARAM_set_auth_level;
  end;

  X509_VERIFY_PARAM_add0_policy := LoadLibCryptoFunction('X509_VERIFY_PARAM_add0_policy');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add0_policy);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_add0_policy :=  @ERROR_X509_VERIFY_PARAM_add0_policy;
  end;

  X509_VERIFY_PARAM_set_inh_flags := LoadLibCryptoFunction('X509_VERIFY_PARAM_set_inh_flags');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_inh_flags);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set_inh_flags :=  @ERROR_X509_VERIFY_PARAM_set_inh_flags;
  end;

  X509_VERIFY_PARAM_get_inh_flags := LoadLibCryptoFunction('X509_VERIFY_PARAM_get_inh_flags');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_inh_flags);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get_inh_flags :=  @ERROR_X509_VERIFY_PARAM_get_inh_flags;
  end;

  X509_VERIFY_PARAM_set1_host := LoadLibCryptoFunction('X509_VERIFY_PARAM_set1_host');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_host);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set1_host :=  @ERROR_X509_VERIFY_PARAM_set1_host;
  end;

  X509_VERIFY_PARAM_add1_host := LoadLibCryptoFunction('X509_VERIFY_PARAM_add1_host');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add1_host);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_add1_host :=  @ERROR_X509_VERIFY_PARAM_add1_host;
  end;

  X509_VERIFY_PARAM_set_hostflags := LoadLibCryptoFunction('X509_VERIFY_PARAM_set_hostflags');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_hostflags);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set_hostflags :=  @ERROR_X509_VERIFY_PARAM_set_hostflags;
  end;

  X509_VERIFY_PARAM_get_hostflags := LoadLibCryptoFunction('X509_VERIFY_PARAM_get_hostflags');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_hostflags);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get_hostflags :=  @ERROR_X509_VERIFY_PARAM_get_hostflags;
  end;

  X509_VERIFY_PARAM_get0_peername := LoadLibCryptoFunction('X509_VERIFY_PARAM_get0_peername');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_peername);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get0_peername :=  @ERROR_X509_VERIFY_PARAM_get0_peername;
  end;

  X509_VERIFY_PARAM_move_peername := LoadLibCryptoFunction('X509_VERIFY_PARAM_move_peername');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_move_peername);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_move_peername :=  @ERROR_X509_VERIFY_PARAM_move_peername;
  end;

  X509_VERIFY_PARAM_set1_email := LoadLibCryptoFunction('X509_VERIFY_PARAM_set1_email');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_email);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set1_email :=  @ERROR_X509_VERIFY_PARAM_set1_email;
  end;

  X509_VERIFY_PARAM_set1_ip := LoadLibCryptoFunction('X509_VERIFY_PARAM_set1_ip');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_ip);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set1_ip :=  @ERROR_X509_VERIFY_PARAM_set1_ip;
  end;

  X509_VERIFY_PARAM_set1_ip_asc := LoadLibCryptoFunction('X509_VERIFY_PARAM_set1_ip_asc');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_ip_asc);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_set1_ip_asc :=  @ERROR_X509_VERIFY_PARAM_set1_ip_asc;
  end;

  X509_VERIFY_PARAM_get_depth := LoadLibCryptoFunction('X509_VERIFY_PARAM_get_depth');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_depth);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get_depth :=  @ERROR_X509_VERIFY_PARAM_get_depth;
  end;

  X509_VERIFY_PARAM_get_auth_level := LoadLibCryptoFunction('X509_VERIFY_PARAM_get_auth_level');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_auth_level);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get_auth_level :=  @ERROR_X509_VERIFY_PARAM_get_auth_level;
  end;

  X509_VERIFY_PARAM_get0_name := LoadLibCryptoFunction('X509_VERIFY_PARAM_get0_name');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_name);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get0_name :=  @ERROR_X509_VERIFY_PARAM_get0_name;
  end;

  X509_VERIFY_PARAM_add0_table := LoadLibCryptoFunction('X509_VERIFY_PARAM_add0_table');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add0_table);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_add0_table :=  @ERROR_X509_VERIFY_PARAM_add0_table;
  end;

  X509_VERIFY_PARAM_get_count := LoadLibCryptoFunction('X509_VERIFY_PARAM_get_count');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_count);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get_count :=  @ERROR_X509_VERIFY_PARAM_get_count;
  end;

  X509_VERIFY_PARAM_get0 := LoadLibCryptoFunction('X509_VERIFY_PARAM_get0');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_get0 :=  @ERROR_X509_VERIFY_PARAM_get0;
  end;

  X509_VERIFY_PARAM_lookup := LoadLibCryptoFunction('X509_VERIFY_PARAM_lookup');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_lookup);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_lookup :=  @ERROR_X509_VERIFY_PARAM_lookup;
  end;

  X509_VERIFY_PARAM_table_cleanup := LoadLibCryptoFunction('X509_VERIFY_PARAM_table_cleanup');
  FuncLoadError := not assigned(X509_VERIFY_PARAM_table_cleanup);
  if FuncLoadError then
  begin
    X509_VERIFY_PARAM_table_cleanup :=  @ERROR_X509_VERIFY_PARAM_table_cleanup;
  end;

  X509_policy_tree_free := LoadLibCryptoFunction('X509_policy_tree_free');
  FuncLoadError := not assigned(X509_policy_tree_free);
  if FuncLoadError then
  begin
    X509_policy_tree_free :=  @ERROR_X509_policy_tree_free;
  end;

  X509_policy_tree_level_count := LoadLibCryptoFunction('X509_policy_tree_level_count');
  FuncLoadError := not assigned(X509_policy_tree_level_count);
  if FuncLoadError then
  begin
    X509_policy_tree_level_count :=  @ERROR_X509_policy_tree_level_count;
  end;

  X509_policy_tree_get0_level := LoadLibCryptoFunction('X509_policy_tree_get0_level');
  FuncLoadError := not assigned(X509_policy_tree_get0_level);
  if FuncLoadError then
  begin
    X509_policy_tree_get0_level :=  @ERROR_X509_policy_tree_get0_level;
  end;

  X509_policy_level_node_count := LoadLibCryptoFunction('X509_policy_level_node_count');
  FuncLoadError := not assigned(X509_policy_level_node_count);
  if FuncLoadError then
  begin
    X509_policy_level_node_count :=  @ERROR_X509_policy_level_node_count;
  end;

  X509_policy_level_get0_node := LoadLibCryptoFunction('X509_policy_level_get0_node');
  FuncLoadError := not assigned(X509_policy_level_get0_node);
  if FuncLoadError then
  begin
    X509_policy_level_get0_node :=  @ERROR_X509_policy_level_get0_node;
  end;

  X509_policy_node_get0_policy := LoadLibCryptoFunction('X509_policy_node_get0_policy');
  FuncLoadError := not assigned(X509_policy_node_get0_policy);
  if FuncLoadError then
  begin
    X509_policy_node_get0_policy :=  @ERROR_X509_policy_node_get0_policy;
  end;

  X509_policy_node_get0_parent := LoadLibCryptoFunction('X509_policy_node_get0_parent');
  FuncLoadError := not assigned(X509_policy_node_get0_parent);
  if FuncLoadError then
  begin
    X509_policy_node_get0_parent :=  @ERROR_X509_policy_node_get0_parent;
  end;

end;

procedure UnLoad;
begin
{$MINENUMSIZE 4}
  X509_STORE_set_depth := nil;
  X509_STORE_CTX_set_depth := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_STORE_CTX_get_app_data := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_OBJECT_up_ref_count := nil;
  X509_OBJECT_new := nil;
  X509_OBJECT_free := nil;
  X509_OBJECT_get_type := nil;
  X509_OBJECT_get0_X509 := nil;
  X509_OBJECT_set1_X509 := nil;
  X509_OBJECT_get0_X509_CRL := nil;
  X509_OBJECT_set1_X509_CRL := nil;
  X509_STORE_new := nil;
  X509_STORE_free := nil;
  X509_STORE_lock := nil;
  X509_STORE_unlock := nil;
  X509_STORE_up_ref := nil;
  X509_STORE_set_flags := nil;
  X509_STORE_set_purpose := nil;
  X509_STORE_set_trust := nil;
  X509_STORE_set1_param := nil;
  X509_STORE_get0_param := nil;
  X509_STORE_set_verify := nil;
  X509_STORE_CTX_set_verify := nil;
  X509_STORE_get_verify := nil;
  X509_STORE_set_verify_cb := nil;
  X509_STORE_get_verify_cb := nil;
  X509_STORE_set_get_issuer := nil;
  X509_STORE_get_get_issuer := nil;
  X509_STORE_set_check_issued := nil;
  X509_STORE_get_check_issued := nil;
  X509_STORE_set_check_revocation := nil;
  X509_STORE_get_check_revocation := nil;
  X509_STORE_set_get_crl := nil;
  X509_STORE_get_get_crl := nil;
  X509_STORE_set_check_crl := nil;
  X509_STORE_get_check_crl := nil;
  X509_STORE_set_cert_crl := nil;
  X509_STORE_get_cert_crl := nil;
  X509_STORE_set_check_policy := nil;
  X509_STORE_get_check_policy := nil;
  X509_STORE_set_cleanup := nil;
  X509_STORE_get_cleanup := nil;
  X509_STORE_set_ex_data := nil;
  X509_STORE_get_ex_data := nil;
  X509_STORE_CTX_new := nil;
  X509_STORE_CTX_get1_issuer := nil;
  X509_STORE_CTX_free := nil;
  X509_STORE_CTX_cleanup := nil;
  X509_STORE_CTX_get0_store := nil;
  X509_STORE_CTX_get0_cert := nil;
  X509_STORE_CTX_set_verify_cb := nil;
  X509_STORE_CTX_get_verify_cb := nil;
  X509_STORE_CTX_get_verify := nil;
  X509_STORE_CTX_get_get_issuer := nil;
  X509_STORE_CTX_get_check_issued := nil;
  X509_STORE_CTX_get_check_revocation := nil;
  X509_STORE_CTX_get_get_crl := nil;
  X509_STORE_CTX_get_check_crl := nil;
  X509_STORE_CTX_get_cert_crl := nil;
  X509_STORE_CTX_get_check_policy := nil;
  X509_STORE_CTX_get_cleanup := nil;
  X509_STORE_add_lookup := nil;
  X509_LOOKUP_hash_dir := nil;
  X509_LOOKUP_file := nil;
  X509_LOOKUP_meth_new := nil;
  X509_LOOKUP_meth_free := nil;
  X509_LOOKUP_meth_set_ctrl := nil;
  X509_LOOKUP_meth_get_ctrl := nil;
  X509_LOOKUP_meth_set_get_by_subject := nil;
  X509_LOOKUP_meth_get_get_by_subject := nil;
  X509_LOOKUP_meth_set_get_by_issuer_serial := nil;
  X509_LOOKUP_meth_get_get_by_issuer_serial := nil;
  X509_LOOKUP_meth_set_get_by_fingerprint := nil;
  X509_LOOKUP_meth_get_get_by_fingerprint := nil;
  X509_LOOKUP_meth_set_get_by_alias := nil;
  X509_LOOKUP_meth_get_get_by_alias := nil;
  X509_STORE_add_cert := nil;
  X509_STORE_add_crl := nil;
  X509_STORE_CTX_get_by_subject := nil;
  X509_STORE_CTX_get_obj_by_subject := nil;
  X509_LOOKUP_ctrl := nil;
  X509_load_cert_file := nil;
  X509_load_crl_file := nil;
  X509_load_cert_crl_file := nil;
  X509_LOOKUP_new := nil;
  X509_LOOKUP_free := nil;
  X509_LOOKUP_init := nil;
  X509_LOOKUP_by_subject := nil;
  X509_LOOKUP_by_issuer_serial := nil;
  X509_LOOKUP_by_fingerprint := nil;
  X509_LOOKUP_by_alias := nil;
  X509_LOOKUP_set_method_data := nil;
  X509_LOOKUP_get_method_data := nil;
  X509_LOOKUP_get_store := nil;
  X509_LOOKUP_shutdown := nil;
  X509_STORE_load_locations := nil;
  X509_STORE_set_default_paths := nil;
  X509_STORE_CTX_set_ex_data := nil;
  X509_STORE_CTX_get_ex_data := nil;
  X509_STORE_CTX_get_error := nil;
  X509_STORE_CTX_set_error := nil;
  X509_STORE_CTX_get_error_depth := nil;
  X509_STORE_CTX_set_error_depth := nil;
  X509_STORE_CTX_get_current_cert := nil;
  X509_STORE_CTX_set_current_cert := nil;
  X509_STORE_CTX_get0_current_issuer := nil;
  X509_STORE_CTX_get0_current_crl := nil;
  X509_STORE_CTX_get0_parent_ctx := nil;
  X509_STORE_CTX_set_cert := nil;
  X509_STORE_CTX_set_purpose := nil;
  X509_STORE_CTX_set_trust := nil;
  X509_STORE_CTX_purpose_inherit := nil;
  X509_STORE_CTX_set_flags := nil;
  X509_STORE_CTX_get0_policy_tree := nil;
  X509_STORE_CTX_get_explicit_policy := nil;
  X509_STORE_CTX_get_num_untrusted := nil;
  X509_STORE_CTX_get0_param := nil;
  X509_STORE_CTX_set0_param := nil;
  X509_STORE_CTX_set_default := nil;
  X509_STORE_CTX_set0_dane := nil;
  X509_VERIFY_PARAM_new := nil;
  X509_VERIFY_PARAM_free := nil;
  X509_VERIFY_PARAM_inherit := nil;
  X509_VERIFY_PARAM_set1 := nil;
  X509_VERIFY_PARAM_set1_name := nil;
  X509_VERIFY_PARAM_set_flags := nil;
  X509_VERIFY_PARAM_clear_flags := nil;
  X509_VERIFY_PARAM_get_flags := nil;
  X509_VERIFY_PARAM_set_purpose := nil;
  X509_VERIFY_PARAM_set_trust := nil;
  X509_VERIFY_PARAM_set_depth := nil;
  X509_VERIFY_PARAM_set_auth_level := nil;
  X509_VERIFY_PARAM_add0_policy := nil;
  X509_VERIFY_PARAM_set_inh_flags := nil;
  X509_VERIFY_PARAM_get_inh_flags := nil;
  X509_VERIFY_PARAM_set1_host := nil;
  X509_VERIFY_PARAM_add1_host := nil;
  X509_VERIFY_PARAM_set_hostflags := nil;
  X509_VERIFY_PARAM_get_hostflags := nil;
  X509_VERIFY_PARAM_get0_peername := nil;
  X509_VERIFY_PARAM_move_peername := nil;
  X509_VERIFY_PARAM_set1_email := nil;
  X509_VERIFY_PARAM_set1_ip := nil;
  X509_VERIFY_PARAM_set1_ip_asc := nil;
  X509_VERIFY_PARAM_get_depth := nil;
  X509_VERIFY_PARAM_get_auth_level := nil;
  X509_VERIFY_PARAM_get0_name := nil;
  X509_VERIFY_PARAM_add0_table := nil;
  X509_VERIFY_PARAM_get_count := nil;
  X509_VERIFY_PARAM_get0 := nil;
  X509_VERIFY_PARAM_lookup := nil;
  X509_VERIFY_PARAM_table_cleanup := nil;
  X509_policy_tree_free := nil;
  X509_policy_tree_level_count := nil;
  X509_policy_tree_get0_level := nil;
  X509_policy_level_node_count := nil;
  X509_policy_level_get0_node := nil;
  X509_policy_node_get0_policy := nil;
  X509_policy_node_get0_parent := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
