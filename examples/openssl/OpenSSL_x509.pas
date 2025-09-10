(* This unit was generated from the source file x509.h2pas 
It should not be modified directly. All changes should be made to x509.h2pas
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


unit OpenSSL_x509;


interface

// Headers for OpenSSL 1.1.1
// x509.h


uses
  OpenSSLAPI,
  OpenSSL_asn1,
  OpenSSL_bio,
  OpenSSL_evp,
  OpenSSL_stack,
  OpenSSL_objects,
  OpenSSL_ossl_typ;

// the following emits are a workaround to a
// name conflict with Win32 API header files
{$IFDEF WINDOWS}
(*$HPPEMIT '#undef X509_EXTENSIONS'*)
(*$HPPEMIT '#undef X509_CERT_PAIR'*)
{$ENDIF}

type
  X509_ALGORS = type Pointer;

const
  (* Flags for X509_get_signature_info() *)
  (* Signature info is valid *)
  X509_SIG_INFO_VALID = $1;
  (* Signature is suitable for TLS use *)
  X509_SIG_INFO_TLS = $2;

  X509_FILETYPE_PEM     = 1;
  X509_FILETYPE_ASN1    = 2;
  X509_FILETYPE_DEFAULT = 3;

  X509v3_KU_DIGITAL_SIGNATURE = $0080;
  X509v3_KU_NON_REPUDIATION   = $0040;
  X509v3_KU_KEY_ENCIPHERMENT  = $0020;
  X509v3_KU_DATA_ENCIPHERMENT = $0010;
  X509v3_KU_KEY_AGREEMENT     = $0008;
  X509v3_KU_KEY_CERT_SIGN     = $0004;
  X509v3_KU_CRL_SIGN          = $0002;
  X509v3_KU_ENCIPHER_ONLY     = $0001;
  X509v3_KU_DECIPHER_ONLY     = $8000;
  X509v3_KU_UNDEF             = $ffff;

  X509_EX_V_NETSCAPE_HACK = $8000;
  X509_EX_V_INIT          = $0001;


  (* standard trust ids *)

  X509_TRUST_DEFAULT      = 0; (* Only valid in purpose settings *)

  X509_TRUST_COMPAT       = 1;
  X509_TRUST_SSL_CLIENT   = 2;
  X509_TRUST_SSL_SERVER   = 3;
  X509_TRUST_EMAIL        = 4;
  X509_TRUST_OBJECT_SIGN  = 5;
  X509_TRUST_OCSP_SIGN    = 6;
  X509_TRUST_OCSP_REQUEST = 7;
  X509_TRUST_TSA          = 8;

  (* Keep these up to date! *)
  X509_TRUST_MIN          = 1;
  X509_TRUST_MAX          = 8;

  (* trust_flags values *)
  X509_TRUST_DYNAMIC      = TOpenSSL_C_UINT(1) shl 0;
  X509_TRUST_DYNAMIC_NAME = TOpenSSL_C_UINT(1) shl 1;
  (* No compat trust if self-signed, preempts "DO_SS" *)
  X509_TRUST_NO_SS_COMPAT = TOpenSSL_C_UINT(1) shl 2;
  (* Compat trust if no explicit accepted trust EKUs *)
  X509_TRUST_DO_SS_COMPAT = TOpenSSL_C_UINT(1) shl 3;
  (* Accept "anyEKU" as a wildcard trust OID *)
  X509_TRUST_OK_ANY_EKU   = TOpenSSL_C_UINT(1) shl 4;

  (* check_trust return codes *)

  X509_TRUST_TRUSTED   = 1;
  X509_TRUST_REJECTED  = 2;
  X509_TRUST_UNTRUSTED = 3;

  (* Flags for X509_print_ex() *)

  X509_FLAG_COMPAT        = 0;
  X509_FLAG_NO_HEADER     = TOpenSSL_C_LONG(1);
  X509_FLAG_NO_VERSION    = TOpenSSL_C_LONG(1) shl 1;
  X509_FLAG_NO_SERIAL     = TOpenSSL_C_LONG(1) shl 2;
  X509_FLAG_NO_SIGNAME    = TOpenSSL_C_LONG(1) shl 3;
  X509_FLAG_NO_ISSUER     = TOpenSSL_C_LONG(1) shl 4;
  X509_FLAG_NO_VALIDITY   = TOpenSSL_C_LONG(1) shl 5;
  X509_FLAG_NO_SUBJECT    = TOpenSSL_C_LONG(1) shl 6;
  X509_FLAG_NO_PUBKEY     = TOpenSSL_C_LONG(1) shl 7;
  X509_FLAG_NO_EXTENSIONS = TOpenSSL_C_LONG(1) shl 8;
  X509_FLAG_NO_SIGDUMP    = TOpenSSL_C_LONG(1) shl 9;
  X509_FLAG_NO_AUX        = TOpenSSL_C_LONG(1) shl 10;
  X509_FLAG_NO_ATTRIBUTES = TOpenSSL_C_LONG(1) shl 11;
  X509_FLAG_NO_IDS        = TOpenSSL_C_LONG(1) shl 12;

  (* Flags specific to X509_NAME_print_ex() *)

  (* The field separator information *)

  XN_FLAG_SEP_MASK       = $f shl 16;

  XN_FLAG_COMPAT         = 0;(* Traditional; use old X509_NAME_print *)
  XN_FLAG_SEP_COMMA_PLUS = 1 shl 16;(* RFC2253 ,+ *)
  XN_FLAG_SEP_CPLUS_SPC  = 2 shl 16;(* ,+ spaced: more readable *)
  XN_FLAG_SEP_SPLUS_SPC  = 3 shl 16;(* ;+ spaced *)
  XN_FLAG_SEP_MULTILINE  = 4 shl 16;(* One line per field *)

  XN_FLAG_DN_REV         = 1 shl 20;(* Reverse DN order *)

  (* How the field name is shown *)

  XN_FLAG_FN_MASK        = $3 shl 21;

  XN_FLAG_FN_SN          = 0;(* Object short name *)
  XN_FLAG_FN_LN          = 1 shl 21;(* Object long name *)
  XN_FLAG_FN_OID         = 2 shl 21;(* Always use OIDs *)
  XN_FLAG_FN_NONE        = 3 shl 21;(* No field names *)

  XN_FLAG_SPC_EQ         = 1 shl 23;(* Put spaces round '=' *)

  {function codes}
  X509_F_ADD_CERT_DIR	= 100;
  X509_F_BY_FILE_CTRL	= 101;
  X509_F_CHECK_NAME_CONSTRAINTS	= 106;
  X509_F_CHECK_POLICY	= 145;
  X509_F_DIR_CTRL	= 102;
  X509_F_GET_CERT_BY_SUBJECT	= 103;
  X509_F_NETSCAPE_SPKI_B64_DECODE	= 129;
  X509_F_NETSCAPE_SPKI_B64_ENCODE	= 130;
  X509_F_X509AT_ADD1_ATTR	= 135;
  X509_F_X509V3_ADD_EXT	= 104;
  X509_F_X509_ATTRIBUTE_CREATE_BY_NID	= 136;
  X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ	= 137;
  X509_F_X509_ATTRIBUTE_CREATE_BY_TXT	= 140;
  X509_F_X509_ATTRIBUTE_GET0_DATA	= 139;
  X509_F_X509_ATTRIBUTE_SET1_DATA	= 138;
  X509_F_X509_CHECK_PRIVATE_KEY	= 128;
  X509_F_X509_CRL_DIFF	= 105;
  X509_F_X509_CRL_PRINT_FP	= 147;
  X509_F_X509_EXTENSION_CREATE_BY_NID	= 108;
  X509_F_X509_EXTENSION_CREATE_BY_OBJ	= 109;
  X509_F_X509_GET_PUBKEY_PARAMETERS	= 110;
  X509_F_X509_LOAD_CERT_CRL_FILE	= 132;
  X509_F_X509_LOAD_CERT_FILE	= 111;
  X509_F_X509_LOAD_CRL_FILE	= 112;
  X509_F_X509_NAME_ADD_ENTRY	= 113;
  X509_F_X509_NAME_ENTRY_CREATE_BY_NID	= 114;
  X509_F_X509_NAME_ENTRY_CREATE_BY_TXT	= 131;
  X509_F_X509_NAME_ENTRY_SET_OBJECT	= 115;
  X509_F_X509_NAME_ONELINE	= 116;
  X509_F_X509_NAME_PRINT	= 117;
  X509_F_X509_PRINT_EX_FP	= 118;
  X509_F_X509_PUBKEY_GET	= 119;
  X509_F_X509_PUBKEY_SET	= 120;
  X509_F_X509_REQ_CHECK_PRIVATE_KEY	= 144;
  X509_F_X509_REQ_PRINT_EX	= 121;
  X509_F_X509_REQ_PRINT_FP	= 122;
  X509_F_X509_REQ_TO_X509	= 123;
  X509_F_X509_STORE_ADD_CERT	= 124;
  X509_F_X509_STORE_ADD_CRL	= 125;
  X509_F_X509_STORE_CTX_GET1_ISSUER	= 146;
  X509_F_X509_STORE_CTX_INIT	= 143;
  X509_F_X509_STORE_CTX_NEW	= 142;
  X509_F_X509_STORE_CTX_PURPOSE_INHERIT	= 134;
  X509_F_X509_TO_X509_REQ	= 126;
  X509_F_X509_TRUST_ADD	= 133;
  X509_F_X509_TRUST_SET	= 141;
  X509_F_X509_VERIFY_CERT	= 127;

  {Reason Codes}
  X509_R_AKID_MISMATCH 				= 110;
  X509_R_BAD_X509_FILETYPE 		        = 100;
  X509_R_BASE64_DECODE_ERROR 		        = 118;
  X509_R_CANT_CHECK_DH_KEY 		        = 114;
  X509_R_CERT_ALREADY_IN_HASH_TABLE 		= 101;
  X509_R_CRL_ALREADY_DELTA 		        = 127;
  X509_R_CRL_VERIFY_FAILURE 		        = 131;
  X509_R_ERR_ASN1_LIB 		                = 102;
  X509_R_IDP_MISMATCH 		                = 128;
  X509_R_INVALID_DIRECTORY 		        = 113;
  X509_R_INVALID_FIELD_NAME 		        = 119;
  X509_R_INVALID_TRUST 		                = 123;
  X509_R_ISSUER_MISMATCH 		        = 129;
  X509_R_KEY_TYPE_MISMATCH	= 115;
  X509_R_KEY_VALUES_MISMATCH	= 116;
  X509_R_LOADING_CERT_DIR	= 103;
  X509_R_LOADING_DEFAULTS	= 104;
  X509_R_METHOD_NOT_SUPPORTED	= 124;
  X509_R_NAME_TOO_LONG	= 134;
  X509_R_NEWER_CRL_NOT_NEWER	= 132;
  X509_R_NO_CERT_SET_FOR_US_TO_VERIFY	= 105;
  X509_R_NO_CRL_NUMBER	= 130;
  X509_R_PUBLIC_KEY_DECODE_ERROR	= 125;
  X509_R_PUBLIC_KEY_ENCODE_ERROR	= 126;
  X509_R_SHOULD_RETRY	= 106;
  X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN	= 107;
  X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY	= 108;
  X509_R_UNKNOWN_KEY_TYPE	= 117;
  X509_R_UNKNOWN_NID	= 109;
  X509_R_UNKNOWN_PURPOSE_ID	= 121;
  X509_R_UNKNOWN_TRUST_ID	= 120;
  X509_R_UNSUPPORTED_ALGORITHM	= 111;
  X509_R_WRONG_LOOKUP_TYPE	= 112;
  X509_R_WRONG_TYPE	= 122;

  (*
   * This determines if we dump fields we don't recognise: RFC2253 requires
   * this.
   *)

  XN_FLAG_DUMP_UNKNOWN_FIELDS = 1 shl 24;

  XN_FLAG_FN_ALIGN = 1 shl 25;(* Align field names to 20
                                             * characters *)

  (* Complete set of RFC2253 flags *)

  XN_FLAG_RFC2253 = ASN1_STRFLGS_RFC2253 or XN_FLAG_SEP_COMMA_PLUS
    or XN_FLAG_DN_REV or XN_FLAG_FN_SN or XN_FLAG_DUMP_UNKNOWN_FIELDS;

  (* readable oneline form *)

  XN_FLAG_ONELINE = ASN1_STRFLGS_RFC2253 or ASN1_STRFLGS_ESC_QUOTE
    or XN_FLAG_SEP_CPLUS_SPC or XN_FLAG_SPC_EQ or XN_FLAG_FN_SN;

  (* readable multiline form *)

  XN_FLAG_MULTILINE = ASN1_STRFLGS_ESC_CTRL or ASN1_STRFLGS_ESC_MSB
    or XN_FLAG_SEP_MULTILINE or XN_FLAG_SPC_EQ or XN_FLAG_FN_LN or XN_FLAG_FN_ALIGN;

  X509_EXT_PACK_UNKNOWN = 1;
  X509_EXT_PACK_STRING  = 2;

type

  X509_val_st = record
    notBefore: PASN1_TIME;
    notAfter: PASN1_TIME;
  end;
  X509_VAL = X509_val_st;
  PX509_VAL = ^X509_VAL;
  PPX509_VAL = ^PX509_VAL;

  X509_SIG = type Pointer; // X509_sig_st
  PX509_SIG = ^X509_SIG;
  PPX509_SIG = ^PX509_SIG;

  X509_NAME_ENTRY = type Pointer; // X509_name_entry_st
  PX509_NAME_ENTRY = ^X509_NAME_ENTRY;
  PPX509_NAME_ENTRY = ^PX509_NAME_ENTRY;

  //DEFINE_STACK_OF(X509_NAME_ENTRY)
  PSTACK_OF_X509_NAME_ENTRY = type pointer;
  //
  //DEFINE_STACK_OF(X509_NAME)
  PSTACK_OF_X509_NAME = type pointer;

  X509_EXTENSION = type Pointer; // X509_extension_st
  PX509_EXTENSION = ^X509_EXTENSION;
  PPX509_EXTENSION = ^PX509_EXTENSION;

  //typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;
  //
  //DEFINE_STACK_OF(X509_EXTENSION)

  X509_ATTRIBUTE = type Pointer; // x509_attributes_st
  PX509_ATTRIBUTE = ^X509_ATTRIBUTE;
  PPX509_ATTRIBUTE = ^PX509_ATTRIBUTE;

  //DEFINE_STACK_OF(X509_ATTRIBUTE)

  X509_REQ_INFO = type Pointer; // X509_req_info_st
  PX509_REQ_INFO = ^X509_REQ_INFO;
  PPX509_REQ_INFO = ^PX509_REQ_INFO;

  X509_CERT_AUX = type Pointer; // x509_cert_aux_st

  X509_CINF = type Pointer; // x509_cinf_st

  //DEFINE_STACK_OF(X509)

  (* This is used for a table of trust checking functions *)

  Px509_trust_st = ^x509_trust_st;
  x509_trust_st = record
    trust: TOpenSSL_C_INT;
    flags: TOpenSSL_C_INT;
    check_trust: function(v1: Px509_trust_st; v2: PX509; v3: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
    name: PAnsiChar;
    arg1: TOpenSSL_C_INT;
    arg2: Pointer;
  end;
  X509_TRUST = x509_trust_st;
  PX509_TRUST = ^X509_TRUST;

  //DEFINE_STACK_OF(X509_TRUST)

  //DEFINE_STACK_OF(X509_REVOKED)
  X509_CRL_INFO = type Pointer; // X509_crl_info_st
  PX509_CRL_INFO = ^X509_CRL_INFO;
  PPX509_CRL_INFO = ^PX509_CRL_INFO;

  //DEFINE_STACK_OF(X509_CRL)

  private_key_st = record
    version: TOpenSSL_C_INT;
    (* The PKCS#8 data types *)
    enc_algor: PX509_ALGOR;
    enc_pkey: PASN1_OCTET_STRING; (* encrypted pub key *)
    (* When decrypted, the following will not be NULL *)
    dec_pkey: PEVP_PKEY;
    (* used to encrypt and decrypt *)
    key_length: TOpenSSL_C_INT;
    key_data: PAnsiChar;
    key_free: TOpenSSL_C_INT;               (* true if we should auto free key_data *)
    (* expanded version of 'enc_algor' *)
    cipher: EVP_CIPHER_INFO;
  end;
  X509_PKEY = private_key_st;
  PX509_PKEY = ^X509_PKEY;

  X509_info_st = record
    x509: PX509;
    crl: PX509_CRL;
    x_pkey: PX509_PKEY;
    enc_cipher: EVP_CIPHER_INFO;
    enc_len: TOpenSSL_C_INT;
    enc_data: PAnsiChar;
  end;
  X509_INFO = X509_info_st;
  PX509_INFO = ^X509_INFO;

  //DEFINE_STACK_OF(X509_INFO)

  (*
   * The next 2 structures and their 8 routines are used to manipulate Netscape's
   * spki structures - useful if you are writing a CA web page
   *)
  Netscape_spkac_st = record
    pubkey: PX509_PUBKEY;
    challenge: PASN1_IA5STRING;  (* challenge sent in atlas >= PR2 *)
  end;
  NETSCAPE_SPKAC = Netscape_spkac_st;
  PNETSCAPE_SPKAC = ^NETSCAPE_SPKAC;

  Netscape_spki_st = record
    spkac: PNETSCAPE_SPKAC;      (* signed public key and challenge *)
    sig_algor: X509_ALGOR;
    signature: PASN1_BIT_STRING;
  end;
  NETSCAPE_SPKI = Netscape_spki_st;
  PNETSCAPE_SPKI = ^NETSCAPE_SPKI;

  (* Netscape certificate sequence structure *)
//  Netscape_certificate_sequence: record
//    type_: PASN1_OBJECT;
//    certs: P --> STACK_OF(X509) <--;
//  end;
//  NETSCAPE_CERT_SEQUENCE = Netscape_certificate_sequence;

  (*- Unused (and iv length is wrong)
  typedef struct CBCParameter_st
          {
          unsigned char iv[8];
          } CBC_PARAM;
  *)

  (* Password based encryption structure *)
  PBEPARAM_st = record
    salt: PASN1_OCTET_STRING;
    iter: PASN1_INTEGER;
  end;
  PBEPARAM = PBEPARAM_st;

  (* Password based encryption V2 structures *)
  PBE2PARAM_st = record
    keyfunc: PX509_ALGOR;
    encryption: X509_ALGOR;
  end;
  PBE2PARAM = PBE2PARAM_st;

  PBKDF2PARAM_st = record
  (* Usually OCTET STRING but could be anything *)
    salt: PASN1_TYPE;
    iter: PASN1_INTEGER;
    keylength: PASN1_INTEGER;
    prf: X509_ALGOR;
  end;
  PBKDF2PARAM = PBKDF2PARAM_st;

  SCRYPT_PARAMS_st = record
    salt: PASN1_OCTET_STRING;
    costParameter: PASN1_INTEGER;
    blockSize: PASN1_INTEGER;
    parallelizationParameter: PASN1_INTEGER;
    keyLength: ASN1_INTEGER;
  end;
  SCRYPT_PARAMS = SCRYPT_PARAMS_st;

  //# define         X509_extract_key(x)     X509_get_pubkey(x)(*****)
  //# define         X509_REQ_extract_key(a) X509_REQ_get_pubkey(a)
  //# define         X509_name_cmp(a,b)      X509_NAME_cmp((a),(b))
  //

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM X509_CRL_set_default_method}
{$EXTERNALSYM X509_CRL_METHOD_free}
{$EXTERNALSYM X509_CRL_set_meth_data}
{$EXTERNALSYM X509_CRL_get_meth_data}
{$EXTERNALSYM X509_verify_cert_error_string}
{$EXTERNALSYM X509_verify}
{$EXTERNALSYM X509_REQ_verify}
{$EXTERNALSYM X509_CRL_verify}
{$EXTERNALSYM NETSCAPE_SPKI_verify}
{$EXTERNALSYM NETSCAPE_SPKI_b64_decode}
{$EXTERNALSYM NETSCAPE_SPKI_b64_encode}
{$EXTERNALSYM NETSCAPE_SPKI_get_pubkey}
{$EXTERNALSYM NETSCAPE_SPKI_set_pubkey}
{$EXTERNALSYM NETSCAPE_SPKI_print}
{$EXTERNALSYM X509_signature_dump}
{$EXTERNALSYM X509_signature_print}
{$EXTERNALSYM X509_sign}
{$EXTERNALSYM X509_sign_ctx}
{$EXTERNALSYM X509_REQ_sign}
{$EXTERNALSYM X509_REQ_sign_ctx}
{$EXTERNALSYM X509_CRL_sign}
{$EXTERNALSYM X509_CRL_sign_ctx}
{$EXTERNALSYM NETSCAPE_SPKI_sign}
{$EXTERNALSYM X509_pubkey_digest}
{$EXTERNALSYM X509_digest}
{$EXTERNALSYM X509_CRL_digest}
{$EXTERNALSYM X509_REQ_digest}
{$EXTERNALSYM X509_NAME_digest}
{$EXTERNALSYM d2i_X509_bio}
{$EXTERNALSYM i2d_X509_bio}
{$EXTERNALSYM d2i_X509_CRL_bio}
{$EXTERNALSYM i2d_X509_CRL_bio}
{$EXTERNALSYM d2i_X509_REQ_bio}
{$EXTERNALSYM i2d_X509_REQ_bio}
{$EXTERNALSYM d2i_RSAPrivateKey_bio}
{$EXTERNALSYM i2d_RSAPrivateKey_bio}
{$EXTERNALSYM d2i_RSAPublicKey_bio}
{$EXTERNALSYM i2d_RSAPublicKey_bio}
{$EXTERNALSYM d2i_RSA_PUBKEY_bio}
{$EXTERNALSYM i2d_RSA_PUBKEY_bio}
{$EXTERNALSYM d2i_DSA_PUBKEY_bio}
{$EXTERNALSYM i2d_DSA_PUBKEY_bio}
{$EXTERNALSYM d2i_DSAPrivateKey_bio}
{$EXTERNALSYM i2d_DSAPrivateKey_bio}
{$EXTERNALSYM d2i_EC_PUBKEY_bio}
{$EXTERNALSYM i2d_EC_PUBKEY_bio}
{$EXTERNALSYM d2i_ECPrivateKey_bio}
{$EXTERNALSYM i2d_ECPrivateKey_bio}
{$EXTERNALSYM d2i_PKCS8_bio}
{$EXTERNALSYM i2d_PKCS8_bio}
{$EXTERNALSYM d2i_PKCS8_PRIV_KEY_INFO_bio}
{$EXTERNALSYM i2d_PKCS8_PRIV_KEY_INFO_bio}
{$EXTERNALSYM i2d_PKCS8PrivateKeyInfo_bio}
{$EXTERNALSYM i2d_PrivateKey_bio}
{$EXTERNALSYM d2i_PrivateKey_bio}
{$EXTERNALSYM i2d_PUBKEY_bio}
{$EXTERNALSYM d2i_PUBKEY_bio}
{$EXTERNALSYM X509_dup}
{$EXTERNALSYM X509_ATTRIBUTE_dup}
{$EXTERNALSYM X509_EXTENSION_dup}
{$EXTERNALSYM X509_CRL_dup}
{$EXTERNALSYM X509_REVOKED_dup}
{$EXTERNALSYM X509_REQ_dup}
{$EXTERNALSYM X509_ALGOR_dup}
{$EXTERNALSYM X509_ALGOR_set0}
{$EXTERNALSYM X509_ALGOR_get0}
{$EXTERNALSYM X509_ALGOR_set_md}
{$EXTERNALSYM X509_ALGOR_cmp}
{$EXTERNALSYM X509_NAME_dup}
{$EXTERNALSYM X509_NAME_ENTRY_dup}
{$EXTERNALSYM X509_cmp_time}
{$EXTERNALSYM X509_cmp_current_time}
{$EXTERNALSYM X509_time_adj}
{$EXTERNALSYM X509_time_adj_ex}
{$EXTERNALSYM X509_gmtime_adj}
{$EXTERNALSYM X509_get_default_cert_area}
{$EXTERNALSYM X509_get_default_cert_dir}
{$EXTERNALSYM X509_get_default_cert_file}
{$EXTERNALSYM X509_get_default_cert_dir_env}
{$EXTERNALSYM X509_get_default_cert_file_env}
{$EXTERNALSYM X509_get_default_private_dir}
{$EXTERNALSYM X509_to_X509_REQ}
{$EXTERNALSYM X509_REQ_to_X509}
{$EXTERNALSYM X509_ALGOR_new}
{$EXTERNALSYM X509_ALGOR_free}
{$EXTERNALSYM d2i_X509_ALGOR}
{$EXTERNALSYM i2d_X509_ALGOR}
{$EXTERNALSYM X509_VAL_new}
{$EXTERNALSYM X509_VAL_free}
{$EXTERNALSYM d2i_X509_VAL}
{$EXTERNALSYM i2d_X509_VAL}
{$EXTERNALSYM X509_PUBKEY_new}
{$EXTERNALSYM X509_PUBKEY_free}
{$EXTERNALSYM d2i_X509_PUBKEY}
{$EXTERNALSYM i2d_X509_PUBKEY}
{$EXTERNALSYM X509_PUBKEY_set}
{$EXTERNALSYM X509_PUBKEY_get0}
{$EXTERNALSYM X509_PUBKEY_get}
{$EXTERNALSYM X509_get_pathlen}
{$EXTERNALSYM i2d_PUBKEY}
{$EXTERNALSYM d2i_PUBKEY}
{$EXTERNALSYM i2d_RSA_PUBKEY}
{$EXTERNALSYM d2i_RSA_PUBKEY}
{$EXTERNALSYM i2d_DSA_PUBKEY}
{$EXTERNALSYM d2i_DSA_PUBKEY}
{$EXTERNALSYM i2d_EC_PUBKEY}
{$EXTERNALSYM d2i_EC_PUBKEY}
{$EXTERNALSYM X509_SIG_new}
{$EXTERNALSYM X509_SIG_free}
{$EXTERNALSYM d2i_X509_SIG}
{$EXTERNALSYM i2d_X509_SIG}
{$EXTERNALSYM X509_SIG_get0}
{$EXTERNALSYM X509_SIG_getm}
{$EXTERNALSYM X509_REQ_INFO_new}
{$EXTERNALSYM X509_REQ_INFO_free}
{$EXTERNALSYM d2i_X509_REQ_INFO}
{$EXTERNALSYM i2d_X509_REQ_INFO}
{$EXTERNALSYM X509_REQ_new}
{$EXTERNALSYM X509_REQ_free}
{$EXTERNALSYM d2i_X509_REQ}
{$EXTERNALSYM i2d_X509_REQ}
{$EXTERNALSYM X509_ATTRIBUTE_new}
{$EXTERNALSYM X509_ATTRIBUTE_free}
{$EXTERNALSYM d2i_X509_ATTRIBUTE}
{$EXTERNALSYM i2d_X509_ATTRIBUTE}
{$EXTERNALSYM X509_ATTRIBUTE_create}
{$EXTERNALSYM X509_EXTENSION_new}
{$EXTERNALSYM X509_EXTENSION_free}
{$EXTERNALSYM d2i_X509_EXTENSION}
{$EXTERNALSYM i2d_X509_EXTENSION}
{$EXTERNALSYM X509_NAME_ENTRY_new}
{$EXTERNALSYM X509_NAME_ENTRY_free}
{$EXTERNALSYM d2i_X509_NAME_ENTRY}
{$EXTERNALSYM i2d_X509_NAME_ENTRY}
{$EXTERNALSYM X509_NAME_new}
{$EXTERNALSYM X509_NAME_free}
{$EXTERNALSYM d2i_X509_NAME}
{$EXTERNALSYM i2d_X509_NAME}
{$EXTERNALSYM X509_NAME_set}
{$EXTERNALSYM X509_new}
{$EXTERNALSYM X509_free}
{$EXTERNALSYM d2i_X509}
{$EXTERNALSYM i2d_X509}
{$EXTERNALSYM X509_set_ex_data}
{$EXTERNALSYM X509_get_ex_data}
{$EXTERNALSYM i2d_X509_AUX}
{$EXTERNALSYM d2i_X509_AUX}
{$EXTERNALSYM i2d_re_X509_tbs}
{$EXTERNALSYM X509_SIG_INFO_get}
{$EXTERNALSYM X509_SIG_INFO_set}
{$EXTERNALSYM X509_get_signature_info}
{$EXTERNALSYM X509_get0_signature}
{$EXTERNALSYM X509_get_signature_nid}
{$EXTERNALSYM X509_trusted}
{$EXTERNALSYM X509_alias_set1}
{$EXTERNALSYM X509_keyid_set1}
{$EXTERNALSYM X509_alias_get0}
{$EXTERNALSYM X509_keyid_get0}
{$EXTERNALSYM X509_TRUST_set}
{$EXTERNALSYM X509_add1_trust_object}
{$EXTERNALSYM X509_add1_reject_object}
{$EXTERNALSYM X509_trust_clear}
{$EXTERNALSYM X509_reject_clear}
{$EXTERNALSYM X509_REVOKED_new}
{$EXTERNALSYM X509_REVOKED_free}
{$EXTERNALSYM d2i_X509_REVOKED}
{$EXTERNALSYM i2d_X509_REVOKED}
{$EXTERNALSYM X509_CRL_INFO_new}
{$EXTERNALSYM X509_CRL_INFO_free}
{$EXTERNALSYM d2i_X509_CRL_INFO}
{$EXTERNALSYM i2d_X509_CRL_INFO}
{$EXTERNALSYM X509_CRL_new}
{$EXTERNALSYM X509_CRL_free}
{$EXTERNALSYM d2i_X509_CRL}
{$EXTERNALSYM i2d_X509_CRL}
{$EXTERNALSYM X509_CRL_add0_revoked}
{$EXTERNALSYM X509_CRL_get0_by_serial}
{$EXTERNALSYM X509_CRL_get0_by_cert}
{$EXTERNALSYM X509_PKEY_new}
{$EXTERNALSYM X509_PKEY_free}
{$EXTERNALSYM X509_INFO_new}
{$EXTERNALSYM X509_INFO_free}
{$EXTERNALSYM X509_NAME_oneline}
{$EXTERNALSYM ASN1_item_digest}
{$EXTERNALSYM ASN1_item_verify}
{$EXTERNALSYM ASN1_item_sign}
{$EXTERNALSYM ASN1_item_sign_ctx}
{$EXTERNALSYM X509_get_version}
{$EXTERNALSYM X509_set_version}
{$EXTERNALSYM X509_set_serialNumber}
{$EXTERNALSYM X509_get_serialNumber}
{$EXTERNALSYM X509_get0_serialNumber}
{$EXTERNALSYM X509_set_issuer_name}
{$EXTERNALSYM X509_get_issuer_name}
{$EXTERNALSYM X509_set_subject_name}
{$EXTERNALSYM X509_get_subject_name}
{$EXTERNALSYM X509_get0_notBefore}
{$EXTERNALSYM X509_getm_notBefore}
{$EXTERNALSYM X509_set1_notBefore}
{$EXTERNALSYM X509_get0_notAfter}
{$EXTERNALSYM X509_getm_notAfter}
{$EXTERNALSYM X509_set1_notAfter}
{$EXTERNALSYM X509_set_pubkey}
{$EXTERNALSYM X509_up_ref}
{$EXTERNALSYM X509_get_signature_type}
{$EXTERNALSYM X509_get_X509_PUBKEY}
{$EXTERNALSYM X509_get0_uids}
{$EXTERNALSYM X509_get0_tbs_sigalg}
{$EXTERNALSYM X509_get0_pubkey}
{$EXTERNALSYM X509_get_pubkey}
{$EXTERNALSYM X509_get0_pubkey_bitstr}
{$EXTERNALSYM X509_certificate_type}
{$EXTERNALSYM X509_REQ_get_version}
{$EXTERNALSYM X509_REQ_set_version}
{$EXTERNALSYM X509_REQ_get_subject_name}
{$EXTERNALSYM X509_REQ_set_subject_name}
{$EXTERNALSYM X509_REQ_get0_signature}
{$EXTERNALSYM X509_REQ_get_signature_nid}
{$EXTERNALSYM i2d_re_X509_REQ_tbs}
{$EXTERNALSYM X509_REQ_set_pubkey}
{$EXTERNALSYM X509_REQ_get_pubkey}
{$EXTERNALSYM X509_REQ_get0_pubkey}
{$EXTERNALSYM X509_REQ_get_X509_PUBKEY}
{$EXTERNALSYM X509_REQ_extension_nid}
{$EXTERNALSYM X509_REQ_get_extension_nids}
{$EXTERNALSYM X509_REQ_set_extension_nids}
{$EXTERNALSYM X509_REQ_get_attr_count}
{$EXTERNALSYM X509_REQ_get_attr_by_NID}
{$EXTERNALSYM X509_REQ_get_attr_by_OBJ}
{$EXTERNALSYM X509_REQ_get_attr}
{$EXTERNALSYM X509_REQ_delete_attr}
{$EXTERNALSYM X509_REQ_add1_attr}
{$EXTERNALSYM X509_REQ_add1_attr_by_OBJ}
{$EXTERNALSYM X509_REQ_add1_attr_by_NID}
{$EXTERNALSYM X509_REQ_add1_attr_by_txt}
{$EXTERNALSYM X509_CRL_set_version}
{$EXTERNALSYM X509_CRL_set_issuer_name}
{$EXTERNALSYM X509_CRL_set1_lastUpdate}
{$EXTERNALSYM X509_CRL_set1_nextUpdate}
{$EXTERNALSYM X509_CRL_sort}
{$EXTERNALSYM X509_CRL_up_ref}
{$EXTERNALSYM X509_CRL_get_version}
{$EXTERNALSYM X509_CRL_get0_lastUpdate}
{$EXTERNALSYM X509_CRL_get0_nextUpdate}
{$EXTERNALSYM X509_CRL_get_issuer}
{$EXTERNALSYM X509_CRL_get0_signature}
{$EXTERNALSYM X509_CRL_get_signature_nid}
{$EXTERNALSYM i2d_re_X509_CRL_tbs}
{$EXTERNALSYM X509_REVOKED_get0_serialNumber}
{$EXTERNALSYM X509_REVOKED_set_serialNumber}
{$EXTERNALSYM X509_REVOKED_get0_revocationDate}
{$EXTERNALSYM X509_REVOKED_set_revocationDate}
{$EXTERNALSYM X509_CRL_diff}
{$EXTERNALSYM X509_REQ_check_private_key}
{$EXTERNALSYM X509_check_private_key}
{$EXTERNALSYM X509_CRL_check_suiteb}
{$EXTERNALSYM X509_issuer_and_serial_cmp}
{$EXTERNALSYM X509_issuer_and_serial_hash}
{$EXTERNALSYM X509_issuer_name_cmp}
{$EXTERNALSYM X509_issuer_name_hash}
{$EXTERNALSYM X509_subject_name_cmp}
{$EXTERNALSYM X509_subject_name_hash}
{$EXTERNALSYM X509_cmp}
{$EXTERNALSYM X509_NAME_cmp}
{$EXTERNALSYM X509_NAME_hash_old}
{$EXTERNALSYM X509_CRL_cmp}
{$EXTERNALSYM X509_CRL_match}
{$EXTERNALSYM X509_aux_print}
{$EXTERNALSYM X509_NAME_print}
{$EXTERNALSYM X509_NAME_print_ex}
{$EXTERNALSYM X509_print_ex}
{$EXTERNALSYM X509_print}
{$EXTERNALSYM X509_ocspid_print}
{$EXTERNALSYM X509_CRL_print_ex}
{$EXTERNALSYM X509_CRL_print}
{$EXTERNALSYM X509_REQ_print_ex}
{$EXTERNALSYM X509_REQ_print}
{$EXTERNALSYM X509_NAME_entry_count}
{$EXTERNALSYM X509_NAME_get_text_by_NID}
{$EXTERNALSYM X509_NAME_get_text_by_OBJ}
{$EXTERNALSYM X509_NAME_get_index_by_NID}
{$EXTERNALSYM X509_NAME_get_index_by_OBJ}
{$EXTERNALSYM X509_NAME_get_entry}
{$EXTERNALSYM X509_NAME_delete_entry}
{$EXTERNALSYM X509_NAME_add_entry}
{$EXTERNALSYM X509_NAME_add_entry_by_OBJ}
{$EXTERNALSYM X509_NAME_add_entry_by_NID}
{$EXTERNALSYM X509_NAME_ENTRY_create_by_txt}
{$EXTERNALSYM X509_NAME_ENTRY_create_by_NID}
{$EXTERNALSYM X509_NAME_add_entry_by_txt}
{$EXTERNALSYM X509_NAME_ENTRY_create_by_OBJ}
{$EXTERNALSYM X509_NAME_ENTRY_set_object}
{$EXTERNALSYM X509_NAME_ENTRY_set_data}
{$EXTERNALSYM X509_NAME_ENTRY_get_object}
{$EXTERNALSYM X509_NAME_ENTRY_get_data}
{$EXTERNALSYM X509_NAME_ENTRY_set}
{$EXTERNALSYM X509_NAME_get0_der}
{$EXTERNALSYM X509_get_ext_count}
{$EXTERNALSYM X509_get_ext_by_NID}
{$EXTERNALSYM X509_get_ext_by_OBJ}
{$EXTERNALSYM X509_get_ext_by_critical}
{$EXTERNALSYM X509_get_ext}
{$EXTERNALSYM X509_delete_ext}
{$EXTERNALSYM X509_add_ext}
{$EXTERNALSYM X509_get_ext_d2i}
{$EXTERNALSYM X509_add1_ext_i2d}
{$EXTERNALSYM X509_CRL_get_ext_count}
{$EXTERNALSYM X509_CRL_get_ext_by_NID}
{$EXTERNALSYM X509_CRL_get_ext_by_OBJ}
{$EXTERNALSYM X509_CRL_get_ext_by_critical}
{$EXTERNALSYM X509_CRL_get_ext}
{$EXTERNALSYM X509_CRL_delete_ext}
{$EXTERNALSYM X509_CRL_add_ext}
{$EXTERNALSYM X509_CRL_get_ext_d2i}
{$EXTERNALSYM X509_CRL_add1_ext_i2d}
{$EXTERNALSYM X509_REVOKED_get_ext_count}
{$EXTERNALSYM X509_REVOKED_get_ext_by_NID}
{$EXTERNALSYM X509_REVOKED_get_ext_by_OBJ}
{$EXTERNALSYM X509_REVOKED_get_ext_by_critical}
{$EXTERNALSYM X509_REVOKED_get_ext}
{$EXTERNALSYM X509_REVOKED_delete_ext}
{$EXTERNALSYM X509_REVOKED_add_ext}
{$EXTERNALSYM X509_REVOKED_get_ext_d2i}
{$EXTERNALSYM X509_REVOKED_add1_ext_i2d}
{$EXTERNALSYM X509_EXTENSION_create_by_NID}
{$EXTERNALSYM X509_EXTENSION_create_by_OBJ}
{$EXTERNALSYM X509_EXTENSION_set_object}
{$EXTERNALSYM X509_EXTENSION_set_critical}
{$EXTERNALSYM X509_EXTENSION_set_data}
{$EXTERNALSYM X509_EXTENSION_get_object}
{$EXTERNALSYM X509_EXTENSION_get_data}
{$EXTERNALSYM X509_EXTENSION_get_critical}
{$EXTERNALSYM X509_ATTRIBUTE_create_by_NID}
{$EXTERNALSYM X509_ATTRIBUTE_create_by_OBJ}
{$EXTERNALSYM X509_ATTRIBUTE_create_by_txt}
{$EXTERNALSYM X509_ATTRIBUTE_set1_object}
{$EXTERNALSYM X509_ATTRIBUTE_set1_data}
{$EXTERNALSYM X509_ATTRIBUTE_get0_data}
{$EXTERNALSYM X509_ATTRIBUTE_count}
{$EXTERNALSYM X509_ATTRIBUTE_get0_object}
{$EXTERNALSYM X509_ATTRIBUTE_get0_type}
{$EXTERNALSYM EVP_PKEY_get_attr_count}
{$EXTERNALSYM EVP_PKEY_get_attr_by_NID}
{$EXTERNALSYM EVP_PKEY_get_attr_by_OBJ}
{$EXTERNALSYM EVP_PKEY_get_attr}
{$EXTERNALSYM EVP_PKEY_delete_attr}
{$EXTERNALSYM EVP_PKEY_add1_attr}
{$EXTERNALSYM EVP_PKEY_add1_attr_by_OBJ}
{$EXTERNALSYM EVP_PKEY_add1_attr_by_NID}
{$EXTERNALSYM EVP_PKEY_add1_attr_by_txt}
{$EXTERNALSYM X509_verify_cert}
{$EXTERNALSYM PKCS5_pbe_set0_algor}
{$EXTERNALSYM PKCS5_pbe_set}
{$EXTERNALSYM PKCS5_pbe2_set}
{$EXTERNALSYM PKCS5_pbe2_set_iv}
{$EXTERNALSYM PKCS5_pbe2_set_scrypt}
{$EXTERNALSYM PKCS5_pbkdf2_set}
{$EXTERNALSYM EVP_PKCS82PKEY}
{$EXTERNALSYM EVP_PKEY2PKCS8}
{$EXTERNALSYM PKCS8_pkey_set0}
{$EXTERNALSYM PKCS8_pkey_get0}
{$EXTERNALSYM PKCS8_pkey_add1_attr_by_NID}
{$EXTERNALSYM X509_PUBKEY_set0_param}
{$EXTERNALSYM X509_PUBKEY_get0_param}
{$EXTERNALSYM X509_check_trust}
{$EXTERNALSYM X509_TRUST_get_count}
{$EXTERNALSYM X509_TRUST_get0}
{$EXTERNALSYM X509_TRUST_get_by_id}
{$EXTERNALSYM X509_TRUST_cleanup}
{$EXTERNALSYM X509_TRUST_get_flags}
{$EXTERNALSYM X509_TRUST_get0_name}
{$EXTERNALSYM X509_TRUST_get_trust}
{$EXTERNALSYM X509_NAME_hash_ex}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure X509_CRL_set_default_method(const meth: PX509_CRL_METHOD); cdecl; external CLibCrypto;
procedure X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl; external CLibCrypto;
procedure X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl; external CLibCrypto;
function X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl; external CLibCrypto;
function X509_verify_cert_error_string(n: TOpenSSL_C_LONG): PAnsiChar; cdecl; external CLibCrypto;
function X509_verify(a: PX509; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_b64_decode(const str: PAnsiChar; len: TOpenSSL_C_INT): PNETSCAPE_SPKI; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PAnsiChar; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_print(out_: PBIO; spki: PNETSCAPE_SPKI): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_signature_dump(bp: PBIO; const sig: PASN1_STRING; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_signature_print(bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_sign(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_pubkey_digest(const data: PX509; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_digest(const data: PX509; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_digest(const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_digest(const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_digest(const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl; external CLibCrypto;
function i2d_X509_bio(bp: PBIO; x509: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl; external CLibCrypto;
function i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl; external CLibCrypto;
function i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; external CLibCrypto;
function i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; external CLibCrypto;
function i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; external CLibCrypto;
function i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): DSA; cdecl; external CLibCrypto;
function i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl; external CLibCrypto;
function i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl; external CLibCrypto;
function i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): EC_KEY; cdecl; external CLibCrypto;
function i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl; external CLibCrypto;
function i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_dup(x509: PX509): PX509; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_dup(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_EXTENSION_dup(ex: PX509_EXTENSION): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_CRL_dup(crl: PX509_CRL): PX509_CRL; cdecl; external CLibCrypto;
function X509_REVOKED_dup(rev: PX509_REVOKED): PX509_REVOKED; cdecl; external CLibCrypto;
function X509_REQ_dup(req: PX509_REQ): PX509_REQ; cdecl; external CLibCrypto;
function X509_ALGOR_dup(xn: PX509_ALGOR): PX509_ALGOR; cdecl; external CLibCrypto;
function X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_ALGOR_get0(const paobj: PPASN1_OBJECT; pptype: POpenSSL_C_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl; external CLibCrypto;
procedure X509_ALGOR_set_md(alg: PX509_ALGOR; const md: PEVP_MD); cdecl; external CLibCrypto;
function X509_ALGOR_cmp(const a: PX509_ALGOR; const b: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_dup(xn: PX509_NAME): PX509_NAME; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_dup(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_cmp_time(const s: PASN1_TIME; t: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_cmp_current_time(const s: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_time_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl; external CLibCrypto;
function X509_time_adj_ex(s: PASN1_TIME; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl; external CLibCrypto;
function X509_gmtime_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG): PASN1_TIME; cdecl; external CLibCrypto;
function X509_get_default_cert_area: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_dir: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_file: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_dir_env: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_file_env: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_private_dir: PAnsiChar; cdecl; external CLibCrypto;
function X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl; external CLibCrypto;
function X509_REQ_to_X509(r: PX509_REQ; days: TOpenSSL_C_INT; pkey: PEVP_PKEY): PX509; cdecl; external CLibCrypto;
function X509_ALGOR_new: PX509_ALGOR; cdecl; external CLibCrypto;
procedure X509_ALGOR_free(v1: PX509_ALGOR); cdecl; external CLibCrypto;
function d2i_X509_ALGOR(a: PPX509_ALGOR; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ALGOR; cdecl; external CLibCrypto;
function i2d_X509_ALGOR(a: PX509_ALGOR; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VAL_new: PX509_VAL; cdecl; external CLibCrypto;
procedure X509_VAL_free(v1: PX509_VAL); cdecl; external CLibCrypto;
function d2i_X509_VAL(a: PPX509_VAL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_VAL; cdecl; external CLibCrypto;
function i2d_X509_VAL(a: PX509_VAL; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_new: PX509_PUBKEY; cdecl; external CLibCrypto;
procedure X509_PUBKEY_free(v1: PX509_PUBKEY); cdecl; external CLibCrypto;
function d2i_X509_PUBKEY(a: PPX509_PUBKEY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_PUBKEY; cdecl; external CLibCrypto;
function i2d_X509_PUBKEY(a: PX509_PUBKEY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_get_pathlen(x: PX509): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function i2d_PUBKEY(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PUBKEY(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_RSA_PUBKEY(a: PRSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSA_PUBKEY(a: PPRSA; const pp: PPByte; length: TOpenSSL_C_LONG): PRSA; cdecl; external CLibCrypto;
function i2d_DSA_PUBKEY(a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSA_PUBKEY(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function i2d_EC_PUBKEY(a: EC_KEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_EC_PUBKEY(a: PPEC_KEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEC_KEY; cdecl; external CLibCrypto;
function X509_SIG_new: PX509_SIG; cdecl; external CLibCrypto;
procedure X509_SIG_free(v1: PX509_SIG); cdecl; external CLibCrypto;
function d2i_X509_SIG(a: PPX509_SIG; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_SIG; cdecl; external CLibCrypto;
function i2d_X509_SIG(a: PX509_SIG; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_SIG_get0(const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl; external CLibCrypto;
procedure X509_SIG_getm(sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl; external CLibCrypto;
function X509_REQ_INFO_new: PX509_REQ_INFO; cdecl; external CLibCrypto;
procedure X509_REQ_INFO_free(v1: PX509_REQ_INFO); cdecl; external CLibCrypto;
function d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ_INFO; cdecl; external CLibCrypto;
function i2d_X509_REQ_INFO(a: PX509_REQ_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_new: PX509_REQ; cdecl; external CLibCrypto;
procedure X509_REQ_free(v1: PX509_REQ); cdecl; external CLibCrypto;
function d2i_X509_REQ(a: PPX509_REQ; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ; cdecl; external CLibCrypto;
function i2d_X509_REQ(a: PX509_REQ; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl; external CLibCrypto;
procedure X509_ATTRIBUTE_free(v1: PX509_ATTRIBUTE); cdecl; external CLibCrypto;
function d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create(nid: TOpenSSL_C_INT; trtype: TOpenSSL_C_INT; value: Pointer): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_EXTENSION_new: PX509_EXTENSION; cdecl; external CLibCrypto;
procedure X509_EXTENSION_free(v1: PX509_EXTENSION); cdecl; external CLibCrypto;
function d2i_X509_EXTENSION(a: PPX509_EXTENSION; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_EXTENSION; cdecl; external CLibCrypto;
function i2d_X509_EXTENSION(a: PX509_EXTENSION; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl; external CLibCrypto;
procedure X509_NAME_ENTRY_free(v1: PX509_NAME_ENTRY); cdecl; external CLibCrypto;
function d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_new: PX509_NAME; cdecl; external CLibCrypto;
procedure X509_NAME_free(v1: PX509_NAME); cdecl; external CLibCrypto;
function d2i_X509_NAME(a: PPX509_NAME; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME; cdecl; external CLibCrypto;
function i2d_X509_NAME(a: PX509_NAME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_new: PX509; cdecl; external CLibCrypto;
procedure X509_free(v1: PX509); cdecl; external CLibCrypto;
function d2i_X509(a: PPX509; const in_: PPByte; len: TOpenSSL_C_LONG): PX509; cdecl; external CLibCrypto;
function i2d_X509(a: PX509; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_set_ex_data(r: PX509; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ex_data(r: PX509; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function i2d_X509_AUX(a: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_AUX(a: PPX509; const pp: PPByte; length: TOpenSSL_C_LONG): PX509; cdecl; external CLibCrypto;
function i2d_re_X509_tbs(x: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_SIG_INFO_get(const siginf: PX509_SIG_INFO; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TOpenSSL_C_INT; pknid: TOpenSSL_C_INT; secbits: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT32); cdecl; external CLibCrypto;
function X509_get_signature_info(x: PX509; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl; external CLibCrypto;
function X509_get_signature_nid(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_trusted(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_alias_set1(x: PX509; const name: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_keyid_set1(x: PX509; const id: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_alias_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function X509_keyid_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function X509_TRUST_set(t: POpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_add1_trust_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_add1_reject_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_trust_clear(x: PX509); cdecl; external CLibCrypto;
procedure X509_reject_clear(x: PX509); cdecl; external CLibCrypto;
function X509_REVOKED_new: PX509_REVOKED; cdecl; external CLibCrypto;
procedure X509_REVOKED_free(v1: PX509_REVOKED); cdecl; external CLibCrypto;
function d2i_X509_REVOKED(a: PPX509_REVOKED; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REVOKED; cdecl; external CLibCrypto;
function i2d_X509_REVOKED(a: PX509_REVOKED; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_INFO_new: PX509_CRL_INFO; cdecl; external CLibCrypto;
procedure X509_CRL_INFO_free(v1: PX509_CRL_INFO); cdecl; external CLibCrypto;
function d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL_INFO; cdecl; external CLibCrypto;
function i2d_X509_CRL_INFO(a: PX509_CRL_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_new: PX509_CRL; cdecl; external CLibCrypto;
procedure X509_CRL_free(v1: PX509_CRL); cdecl; external CLibCrypto;
function d2i_X509_CRL(a: PPX509_CRL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL; cdecl; external CLibCrypto;
function i2d_X509_CRL(a: PX509_CRL; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PKEY_new: PX509_PKEY; cdecl; external CLibCrypto;
procedure X509_PKEY_free(a: PX509_PKEY); cdecl; external CLibCrypto;
function X509_INFO_new: PX509_INFO; cdecl; external CLibCrypto;
procedure X509_INFO_free(a: PX509_INFO); cdecl; external CLibCrypto;
function X509_NAME_oneline(const a: PX509_NAME; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function ASN1_item_digest(const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_verify(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_sign(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_sign_ctx(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_version(const x: PX509): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function X509_set_version(x: PX509; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl; external CLibCrypto;
function X509_get0_serialNumber(const x: PX509): PASN1_INTEGER; cdecl; external CLibCrypto;
function X509_set_issuer_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_issuer_name(const a: PX509): PX509_NAME; cdecl; external CLibCrypto;
function X509_set_subject_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_subject_name(const a: PX509): PX509_NAME; cdecl; external CLibCrypto;
function X509_get0_notBefore(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_getm_notBefore(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_set1_notBefore(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get0_notAfter(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_getm_notAfter(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_set1_notAfter(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_up_ref(x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_signature_type(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_X509_PUBKEY(const x: PX509): PX509_PUBKEY; cdecl; external CLibCrypto;
procedure X509_get0_uids(const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl; external CLibCrypto;
function X509_get0_tbs_sigalg(const x: PX509): PX509_ALGOR; cdecl; external CLibCrypto;
function X509_get0_pubkey(const x: PX509): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_get0_pubkey_bitstr(const x: PX509): PASN1_BIT_STRING; cdecl; external CLibCrypto;
function X509_certificate_type(const x: PX509; const pubkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_version(const req: PX509_REQ): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function X509_REQ_set_version(x: PX509_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_subject_name(const req: PX509_REQ): PX509_NAME; cdecl; external CLibCrypto;
function X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_REQ_get0_signature(const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl; external CLibCrypto;
function X509_REQ_get_signature_nid(const req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl; external CLibCrypto;
function X509_REQ_extension_nid(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_extension_nids: POpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_REQ_set_extension_nids(nids: POpenSSL_C_INT); cdecl; external CLibCrypto;
function X509_REQ_get_attr_count(const req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_attr_by_NID(const req: PX509_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_attr_by_OBJ(const req: PX509_REQ; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_attr(const req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_REQ_delete_attr(req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_add1_attr_by_txt(req: PX509_REQ; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set_version(x: PX509_CRL; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set1_lastUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set1_nextUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_sort(crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_up_ref(crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_version(const crl: PX509_CRL): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function X509_CRL_get0_lastUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl; external CLibCrypto;
function X509_CRL_get0_nextUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl; external CLibCrypto;
function X509_CRL_get_issuer(const crl: PX509_CRL): PX509_NAME; cdecl; external CLibCrypto;
procedure X509_CRL_get0_signature(const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl; external CLibCrypto;
function X509_CRL_get_signature_nid(const crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get0_serialNumber(const x: PX509_REVOKED): PASN1_INTEGER; cdecl; external CLibCrypto;
function X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get0_revocationDate(const x: PX509_REVOKED): PASN1_TIME; cdecl; external CLibCrypto;
function X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PX509_CRL; cdecl; external CLibCrypto;
function X509_REQ_check_private_key(x509: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_private_key(const x509: PX509; const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_issuer_and_serial_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_issuer_and_serial_hash(a: PX509): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function X509_issuer_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_issuer_name_hash(a: PX509): TOpenSSL_C_uLONG; cdecl; external CLibCrypto;
function X509_subject_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_subject_name_hash(x: PX509): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function X509_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_cmp(const a: PX509_NAME; const b: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_hash_old(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function X509_CRL_cmp(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_match(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_aux_print(out_: PBIO; x: PX509; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_print(bp: PBIO; const name: PX509_NAME; obase: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_print_ex(out_: PBIO; const nm: PX509_NAME; indent: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_print_ex(bp: PBIO; x: PX509; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ocspid_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_print_ex(out_: PBIO; x: PX509_CRL; nmflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_print(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_print(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_entry_count(const name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_text_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_index_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_entry(const name: PX509_NAME; loc: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_delete_entry(name: PX509_NAME; loc: TOpenSSL_C_INT): pX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_add_entry(name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_add_entry_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_add_entry_by_txt(name: PX509_NAME; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_get_object(const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_get_data(const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_set(const ne: PX509_NAME_ENTRY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get0_der(nm: PX509_NAME; const pder: PPByte; pderlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_count(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_by_NID(const x: PX509; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_by_OBJ(const x: PX509; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_by_critical(const x: PX509; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext(const x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_delete_ext(x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_d2i(const x: PX509; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_add1_ext_i2d(x: PX509; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_count(const x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_by_NID(const x: PX509_CRL; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_by_OBJ(const x: X509_CRL; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_by_critical(const x: PX509_CRL; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext(const x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_CRL_delete_ext(x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_d2i(const x: PX509_CRL; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_count(const x: PX509_REVOKED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_by_NID(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_by_OBJ(const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_by_critical(const x: PX509_REVOKED; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext(const x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_d2i(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_EXTENSION_set_object(ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl; external CLibCrypto;
function X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function X509_EXTENSION_get_critical(const ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; const atrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; data: Pointer): Pointer; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_count(const attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT): PASN1_TYPE; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr_count(const key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr_by_NID(const key: PEVP_PKEY; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr_by_OBJ(const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr(const key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_verify_cert(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_pbe_set(alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbe2_set(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbe2_set_iv(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; prf_nid: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbe2_set_scrypt(const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbkdf2_set(iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; prf_nid: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function EVP_PKCS82PKEY(const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TOpenSSL_C_INT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS8_pkey_get0(const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_trust(x: PX509; id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_TRUST_get_count: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_TRUST_get0(idx: TOpenSSL_C_INT): PX509_TRUST; cdecl; external CLibCrypto;
function X509_TRUST_get_by_id(id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_TRUST_cleanup; cdecl; external CLibCrypto;
function X509_TRUST_get_flags(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_TRUST_get0_name(const xp: PX509_TRUST): PAnsiChar; cdecl; external CLibCrypto;
function X509_TRUST_get_trust(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  X509_CRL_set_default_method: procedure (const meth: PX509_CRL_METHOD); cdecl = nil;
  X509_CRL_METHOD_free: procedure (m: PX509_CRL_METHOD); cdecl = nil;
  X509_CRL_set_meth_data: procedure (crl: PX509_CRL; dat: Pointer); cdecl = nil;
  X509_CRL_get_meth_data: function (crl: PX509_CRL): Pointer; cdecl = nil;
  X509_verify_cert_error_string: function (n: TOpenSSL_C_LONG): PAnsiChar; cdecl = nil;
  X509_verify: function (a: PX509; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_verify: function (a: PX509_REQ; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_verify: function (a: PX509_CRL; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  NETSCAPE_SPKI_verify: function (a: PNETSCAPE_SPKI; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  NETSCAPE_SPKI_b64_decode: function (const str: PAnsiChar; len: TOpenSSL_C_INT): PNETSCAPE_SPKI; cdecl = nil;
  NETSCAPE_SPKI_b64_encode: function (x: PNETSCAPE_SPKI): PAnsiChar; cdecl = nil;
  NETSCAPE_SPKI_get_pubkey: function (x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl = nil;
  NETSCAPE_SPKI_set_pubkey: function (x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  NETSCAPE_SPKI_print: function (out_: PBIO; spki: PNETSCAPE_SPKI): TOpenSSL_C_INT; cdecl = nil;
  X509_signature_dump: function (bp: PBIO; const sig: PASN1_STRING; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_signature_print: function (bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl = nil;
  X509_sign: function (x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  X509_sign_ctx: function (x: PX509; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_sign: function (x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_sign_ctx: function (x: PX509_REQ; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_sign: function (x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_sign_ctx: function (x: PX509_CRL; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil;
  NETSCAPE_SPKI_sign: function (x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  X509_pubkey_digest: function (const data: PX509; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  X509_digest: function (const data: PX509; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_digest: function (const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_digest: function (const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_digest: function (const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  d2i_X509_bio: function (bp: PBIO; x509: PPX509): PX509; cdecl = nil;
  i2d_X509_bio: function (bp: PBIO; x509: PX509): TOpenSSL_C_INT; cdecl = nil;
  d2i_X509_CRL_bio: function (bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl = nil;
  i2d_X509_CRL_bio: function (bp: PBIO; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  d2i_X509_REQ_bio: function (bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl = nil;
  i2d_X509_REQ_bio: function (bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  d2i_RSAPrivateKey_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil;
  i2d_RSAPrivateKey_bio: function (bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  d2i_RSAPublicKey_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil;
  i2d_RSAPublicKey_bio: function (bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  d2i_RSA_PUBKEY_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil;
  i2d_RSA_PUBKEY_bio: function (bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  d2i_DSA_PUBKEY_bio: function (bp: PBIO; dsa: PPDSA): DSA; cdecl = nil;
  i2d_DSA_PUBKEY_bio: function (bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl = nil;
  d2i_DSAPrivateKey_bio: function (bp: PBIO; dsa: PPDSA): PDSA; cdecl = nil;
  i2d_DSAPrivateKey_bio: function (bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl = nil;
  d2i_EC_PUBKEY_bio: function (bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl = nil;
  i2d_EC_PUBKEY_bio: function (bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  d2i_ECPrivateKey_bio: function (bp: PBIO; eckey: PPEC_KEY): EC_KEY; cdecl = nil;
  i2d_ECPrivateKey_bio: function (bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  d2i_PKCS8_bio: function (bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl = nil;
  i2d_PKCS8_bio: function (bp: PBIO; p8: PX509_SIG): TOpenSSL_C_INT; cdecl = nil;
  d2i_PKCS8_PRIV_KEY_INFO_bio: function (bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  i2d_PKCS8_PRIV_KEY_INFO_bio: function (bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = nil;
  i2d_PKCS8PrivateKeyInfo_bio: function (bp: PBIO; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  i2d_PrivateKey_bio: function (bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  d2i_PrivateKey_bio: function (bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  i2d_PUBKEY_bio: function (bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  d2i_PUBKEY_bio: function (bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  X509_dup: function (x509: PX509): PX509; cdecl = nil;
  X509_ATTRIBUTE_dup: function (xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl = nil;
  X509_EXTENSION_dup: function (ex: PX509_EXTENSION): PX509_EXTENSION; cdecl = nil;
  X509_CRL_dup: function (crl: PX509_CRL): PX509_CRL; cdecl = nil;
  X509_REVOKED_dup: function (rev: PX509_REVOKED): PX509_REVOKED; cdecl = nil;
  X509_REQ_dup: function (req: PX509_REQ): PX509_REQ; cdecl = nil;
  X509_ALGOR_dup: function (xn: PX509_ALGOR): PX509_ALGOR; cdecl = nil;
  X509_ALGOR_set0: function (alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer): TOpenSSL_C_INT; cdecl = nil;
  X509_ALGOR_get0: procedure (const paobj: PPASN1_OBJECT; pptype: POpenSSL_C_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl = nil;
  X509_ALGOR_set_md: procedure (alg: PX509_ALGOR; const md: PEVP_MD); cdecl = nil;
  X509_ALGOR_cmp: function (const a: PX509_ALGOR; const b: PX509_ALGOR): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_dup: function (xn: PX509_NAME): PX509_NAME; cdecl = nil;
  X509_NAME_ENTRY_dup: function (ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl = nil;
  X509_cmp_time: function (const s: PASN1_TIME; t: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = nil;
  X509_cmp_current_time: function (const s: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  X509_time_adj: function (s: PASN1_TIME; adj: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl = nil;
  X509_time_adj_ex: function (s: PASN1_TIME; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl = nil;
  X509_gmtime_adj: function (s: PASN1_TIME; adj: TOpenSSL_C_LONG): PASN1_TIME; cdecl = nil;
  X509_get_default_cert_area: function : PAnsiChar; cdecl = nil;
  X509_get_default_cert_dir: function : PAnsiChar; cdecl = nil;
  X509_get_default_cert_file: function : PAnsiChar; cdecl = nil;
  X509_get_default_cert_dir_env: function : PAnsiChar; cdecl = nil;
  X509_get_default_cert_file_env: function : PAnsiChar; cdecl = nil;
  X509_get_default_private_dir: function : PAnsiChar; cdecl = nil;
  X509_to_X509_REQ: function (x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl = nil;
  X509_REQ_to_X509: function (r: PX509_REQ; days: TOpenSSL_C_INT; pkey: PEVP_PKEY): PX509; cdecl = nil;
  X509_ALGOR_new: function : PX509_ALGOR; cdecl = nil;
  X509_ALGOR_free: procedure (v1: PX509_ALGOR); cdecl = nil;
  d2i_X509_ALGOR: function (a: PPX509_ALGOR; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ALGOR; cdecl = nil;
  i2d_X509_ALGOR: function (a: PX509_ALGOR; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_VAL_new: function : PX509_VAL; cdecl = nil;
  X509_VAL_free: procedure (v1: PX509_VAL); cdecl = nil;
  d2i_X509_VAL: function (a: PPX509_VAL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_VAL; cdecl = nil;
  i2d_X509_VAL: function (a: PX509_VAL; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_PUBKEY_new: function : PX509_PUBKEY; cdecl = nil;
  X509_PUBKEY_free: procedure (v1: PX509_PUBKEY); cdecl = nil;
  d2i_X509_PUBKEY: function (a: PPX509_PUBKEY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_PUBKEY; cdecl = nil;
  i2d_X509_PUBKEY: function (a: PX509_PUBKEY; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_PUBKEY_set: function (x: PPX509_PUBKEY; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_PUBKEY_get0: function (key: PX509_PUBKEY): PEVP_PKEY; cdecl = nil;
  X509_PUBKEY_get: function (key: PX509_PUBKEY): PEVP_PKEY; cdecl = nil;
  X509_get_pathlen: function (x: PX509): TOpenSSL_C_LONG; cdecl = nil;
  i2d_PUBKEY: function (a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_PUBKEY: function (a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = nil;
  i2d_RSA_PUBKEY: function (a: PRSA; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_RSA_PUBKEY: function (a: PPRSA; const pp: PPByte; length: TOpenSSL_C_LONG): PRSA; cdecl = nil;
  i2d_DSA_PUBKEY: function (a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_DSA_PUBKEY: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = nil;
  i2d_EC_PUBKEY: function (a: EC_KEY; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_EC_PUBKEY: function (a: PPEC_KEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEC_KEY; cdecl = nil;
  X509_SIG_new: function : PX509_SIG; cdecl = nil;
  X509_SIG_free: procedure (v1: PX509_SIG); cdecl = nil;
  d2i_X509_SIG: function (a: PPX509_SIG; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_SIG; cdecl = nil;
  i2d_X509_SIG: function (a: PX509_SIG; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_SIG_get0: procedure (const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl = nil;
  X509_SIG_getm: procedure (sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl = nil;
  X509_REQ_INFO_new: function : PX509_REQ_INFO; cdecl = nil;
  X509_REQ_INFO_free: procedure (v1: PX509_REQ_INFO); cdecl = nil;
  d2i_X509_REQ_INFO: function (a: PPX509_REQ_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ_INFO; cdecl = nil;
  i2d_X509_REQ_INFO: function (a: PX509_REQ_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_new: function : PX509_REQ; cdecl = nil;
  X509_REQ_free: procedure (v1: PX509_REQ); cdecl = nil;
  d2i_X509_REQ: function (a: PPX509_REQ; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ; cdecl = nil;
  i2d_X509_REQ: function (a: PX509_REQ; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_ATTRIBUTE_new: function : PX509_ATTRIBUTE; cdecl = nil;
  X509_ATTRIBUTE_free: procedure (v1: PX509_ATTRIBUTE); cdecl = nil;
  d2i_X509_ATTRIBUTE: function (a: PPX509_ATTRIBUTE; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ATTRIBUTE; cdecl = nil;
  i2d_X509_ATTRIBUTE: function (a: PX509_ATTRIBUTE; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_ATTRIBUTE_create: function (nid: TOpenSSL_C_INT; trtype: TOpenSSL_C_INT; value: Pointer): PX509_ATTRIBUTE; cdecl = nil;
  X509_EXTENSION_new: function : PX509_EXTENSION; cdecl = nil;
  X509_EXTENSION_free: procedure (v1: PX509_EXTENSION); cdecl = nil;
  d2i_X509_EXTENSION: function (a: PPX509_EXTENSION; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_EXTENSION; cdecl = nil;
  i2d_X509_EXTENSION: function (a: PX509_EXTENSION; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_ENTRY_new: function : PX509_NAME_ENTRY; cdecl = nil;
  X509_NAME_ENTRY_free: procedure (v1: PX509_NAME_ENTRY); cdecl = nil;
  d2i_X509_NAME_ENTRY: function (a: PPX509_NAME_ENTRY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME_ENTRY; cdecl = nil;
  i2d_X509_NAME_ENTRY: function (a: PX509_NAME_ENTRY; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_new: function : PX509_NAME; cdecl = nil;
  X509_NAME_free: procedure (v1: PX509_NAME); cdecl = nil;
  d2i_X509_NAME: function (a: PPX509_NAME; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME; cdecl = nil;
  i2d_X509_NAME: function (a: PX509_NAME; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_set: function (xn: PPX509_NAME; name: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  X509_new: function : PX509; cdecl = nil;
  X509_free: procedure (v1: PX509); cdecl = nil;
  d2i_X509: function (a: PPX509; const in_: PPByte; len: TOpenSSL_C_LONG): PX509; cdecl = nil;
  i2d_X509: function (a: PX509; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_set_ex_data: function (r: PX509; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  X509_get_ex_data: function (r: PX509; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  i2d_X509_AUX: function (a: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_X509_AUX: function (a: PPX509; const pp: PPByte; length: TOpenSSL_C_LONG): PX509; cdecl = nil;
  i2d_re_X509_tbs: function (x: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_SIG_INFO_get: function (const siginf: PX509_SIG_INFO; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  X509_SIG_INFO_set: procedure (siginf: PX509_SIG_INFO; mdnid: TOpenSSL_C_INT; pknid: TOpenSSL_C_INT; secbits: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT32); cdecl = nil;
  X509_get_signature_info: function (x: PX509; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  X509_get0_signature: procedure (var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl = nil;
  X509_get_signature_nid: function (const x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_trusted: function (const x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_alias_set1: function (x: PX509; const name: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_keyid_set1: function (x: PX509; const id: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_alias_get0: function (x: PX509; len: POpenSSL_C_INT): PByte; cdecl = nil;
  X509_keyid_get0: function (x: PX509; len: POpenSSL_C_INT): PByte; cdecl = nil;
  X509_TRUST_set: function (t: POpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_add1_trust_object: function (x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_add1_reject_object: function (x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_trust_clear: procedure (x: PX509); cdecl = nil;
  X509_reject_clear: procedure (x: PX509); cdecl = nil;
  X509_REVOKED_new: function : PX509_REVOKED; cdecl = nil;
  X509_REVOKED_free: procedure (v1: PX509_REVOKED); cdecl = nil;
  d2i_X509_REVOKED: function (a: PPX509_REVOKED; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REVOKED; cdecl = nil;
  i2d_X509_REVOKED: function (a: PX509_REVOKED; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_INFO_new: function : PX509_CRL_INFO; cdecl = nil;
  X509_CRL_INFO_free: procedure (v1: PX509_CRL_INFO); cdecl = nil;
  d2i_X509_CRL_INFO: function (a: PPX509_CRL_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL_INFO; cdecl = nil;
  i2d_X509_CRL_INFO: function (a: PX509_CRL_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_new: function : PX509_CRL; cdecl = nil;
  X509_CRL_free: procedure (v1: PX509_CRL); cdecl = nil;
  d2i_X509_CRL: function (a: PPX509_CRL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL; cdecl = nil;
  i2d_X509_CRL: function (a: PX509_CRL; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_add0_revoked: function (crl: PX509_CRL; rev: PX509_REVOKED): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get0_by_serial: function (crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get0_by_cert: function (crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_PKEY_new: function : PX509_PKEY; cdecl = nil;
  X509_PKEY_free: procedure (a: PX509_PKEY); cdecl = nil;
  X509_INFO_new: function : PX509_INFO; cdecl = nil;
  X509_INFO_free: procedure (a: PX509_INFO); cdecl = nil;
  X509_NAME_oneline: function (const a: PX509_NAME; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  ASN1_item_digest: function (const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_verify: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_sign: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_sign_ctx: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509_get_version: function (const x: PX509): TOpenSSL_C_LONG; cdecl = nil;
  X509_set_version: function (x: PX509; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  X509_set_serialNumber: function (x: PX509; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  X509_get_serialNumber: function (x: PX509): PASN1_INTEGER; cdecl = nil;
  X509_get0_serialNumber: function (const x: PX509): PASN1_INTEGER; cdecl = nil;
  X509_set_issuer_name: function (x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  X509_get_issuer_name: function (const a: PX509): PX509_NAME; cdecl = nil;
  X509_set_subject_name: function (x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  X509_get_subject_name: function (const a: PX509): PX509_NAME; cdecl = nil;
  X509_get0_notBefore: function (const x: PX509): PASN1_TIME; cdecl = nil;
  X509_getm_notBefore: function (const x: PX509): PASN1_TIME; cdecl = nil;
  X509_set1_notBefore: function (x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  X509_get0_notAfter: function (const x: PX509): PASN1_TIME; cdecl = nil;
  X509_getm_notAfter: function (const x: PX509): PASN1_TIME; cdecl = nil;
  X509_set1_notAfter: function (x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  X509_set_pubkey: function (x: PX509; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_up_ref: function (x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_get_signature_type: function (const x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_get_X509_PUBKEY: function (const x: PX509): PX509_PUBKEY; cdecl = nil;
  X509_get0_uids: procedure (const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl = nil;
  X509_get0_tbs_sigalg: function (const x: PX509): PX509_ALGOR; cdecl = nil;
  X509_get0_pubkey: function (const x: PX509): PEVP_PKEY; cdecl = nil;
  X509_get_pubkey: function (x: PX509): PEVP_PKEY; cdecl = nil;
  X509_get0_pubkey_bitstr: function (const x: PX509): PASN1_BIT_STRING; cdecl = nil;
  X509_certificate_type: function (const x: PX509; const pubkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get_version: function (const req: PX509_REQ): TOpenSSL_C_LONG; cdecl = nil;
  X509_REQ_set_version: function (x: PX509_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get_subject_name: function (const req: PX509_REQ): PX509_NAME; cdecl = nil;
  X509_REQ_set_subject_name: function (req: PX509_REQ; name: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get0_signature: procedure (const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl = nil;
  X509_REQ_get_signature_nid: function (const req: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  i2d_re_X509_REQ_tbs: function (req: PX509_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_set_pubkey: function (x: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get_pubkey: function (req: PX509_REQ): PEVP_PKEY; cdecl = nil;
  X509_REQ_get0_pubkey: function (req: PX509_REQ): PEVP_PKEY; cdecl = nil;
  X509_REQ_get_X509_PUBKEY: function (req: PX509_REQ): PX509_PUBKEY; cdecl = nil;
  X509_REQ_extension_nid: function (nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get_extension_nids: function : POpenSSL_C_INT; cdecl = nil;
  X509_REQ_set_extension_nids: procedure (nids: POpenSSL_C_INT); cdecl = nil;
  X509_REQ_get_attr_count: function (const req: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get_attr_by_NID: function (const req: PX509_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get_attr_by_OBJ: function (const req: PX509_REQ; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_get_attr: function (const req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  X509_REQ_delete_attr: function (req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  X509_REQ_add1_attr: function (req: PX509_REQ; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_add1_attr_by_OBJ: function (req: PX509_REQ; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_add1_attr_by_NID: function (req: PX509_REQ; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_add1_attr_by_txt: function (req: PX509_REQ; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_set_version: function (x: PX509_CRL; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_set_issuer_name: function (x: PX509_CRL; name: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_set1_lastUpdate: function (x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_set1_nextUpdate: function (x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_sort: function (crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_up_ref: function (crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get_version: function (const crl: PX509_CRL): TOpenSSL_C_LONG; cdecl = nil;
  X509_CRL_get0_lastUpdate: function (const crl: PX509_CRL): PASN1_TIME; cdecl = nil;
  X509_CRL_get0_nextUpdate: function (const crl: PX509_CRL): PASN1_TIME; cdecl = nil;
  X509_CRL_get_issuer: function (const crl: PX509_CRL): PX509_NAME; cdecl = nil;
  X509_CRL_get0_signature: procedure (const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl = nil;
  X509_CRL_get_signature_nid: function (const crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  i2d_re_X509_CRL_tbs: function (req: PX509_CRL; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get0_serialNumber: function (const x: PX509_REVOKED): PASN1_INTEGER; cdecl = nil;
  X509_REVOKED_set_serialNumber: function (x: PX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get0_revocationDate: function (const x: PX509_REVOKED): PASN1_TIME; cdecl = nil;
  X509_REVOKED_set_revocationDate: function (r: PX509_REVOKED; tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_diff: function (base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PX509_CRL; cdecl = nil;
  X509_REQ_check_private_key: function (x509: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_check_private_key: function (const x509: PX509; const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_check_suiteb: function (crl: PX509_CRL; pk: PEVP_PKEY; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_issuer_and_serial_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_issuer_and_serial_hash: function (a: PX509): TOpenSSL_C_ULONG; cdecl = nil;
  X509_issuer_name_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_issuer_name_hash: function (a: PX509): TOpenSSL_C_uLONG; cdecl = nil;
  X509_subject_name_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_subject_name_hash: function (x: PX509): TOpenSSL_C_ULONG; cdecl = nil;
  X509_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_cmp: function (const a: PX509_NAME; const b: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_hash_old: function (x: PX509_NAME): TOpenSSL_C_ULONG; cdecl = nil;
  X509_CRL_cmp: function (const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_match: function (const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_aux_print: function (out_: PBIO; x: PX509; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_print: function (bp: PBIO; const name: PX509_NAME; obase: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_print_ex: function (out_: PBIO; const nm: PX509_NAME; indent: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_print_ex: function (bp: PBIO; x: PX509; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_print: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_ocspid_print: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_print_ex: function (out_: PBIO; x: PX509_CRL; nmflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_print: function (bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_print_ex: function (bp: PBIO; x: PX509_REQ; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_REQ_print: function (bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_entry_count: function (const name: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_get_text_by_NID: function (name: PX509_NAME; nid: TOpenSSL_C_INT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_get_text_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_get_index_by_NID: function (name: PX509_NAME; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_get_index_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_get_entry: function (const name: PX509_NAME; loc: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = nil;
  X509_NAME_delete_entry: function (name: PX509_NAME; loc: TOpenSSL_C_INT): pX509_NAME_ENTRY; cdecl = nil;
  X509_NAME_add_entry: function (name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_add_entry_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_add_entry_by_NID: function (name: PX509_NAME; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_ENTRY_create_by_txt: function (ne: PPX509_NAME_ENTRY; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = nil;
  X509_NAME_ENTRY_create_by_NID: function (ne: PPX509_NAME_ENTRY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = nil;
  X509_NAME_add_entry_by_txt: function (name: PX509_NAME; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_ENTRY_create_by_OBJ: function (ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = nil;
  X509_NAME_ENTRY_set_object: function (ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_ENTRY_set_data: function (ne: PX509_NAME_ENTRY; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_ENTRY_get_object: function (const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl = nil;
  X509_NAME_ENTRY_get_data: function (const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl = nil;
  X509_NAME_ENTRY_set: function (const ne: PX509_NAME_ENTRY): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_get0_der: function (nm: PX509_NAME; const pder: PPByte; pderlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  X509_get_ext_count: function (const x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_get_ext_by_NID: function (const x: PX509; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_get_ext_by_OBJ: function (const x: PX509; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_get_ext_by_critical: function (const x: PX509; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_get_ext: function (const x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = nil;
  X509_delete_ext: function (x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = nil;
  X509_add_ext: function (x: PX509; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_get_ext_d2i: function (const x: PX509; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = nil;
  X509_add1_ext_i2d: function (x: PX509; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get_ext_count: function (const x: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get_ext_by_NID: function (const x: PX509_CRL; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get_ext_by_OBJ: function (const x: X509_CRL; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get_ext_by_critical: function (const x: PX509_CRL; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get_ext: function (const x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = nil;
  X509_CRL_delete_ext: function (x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = nil;
  X509_CRL_add_ext: function (x: PX509_CRL; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_CRL_get_ext_d2i: function (const x: PX509_CRL; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = nil;
  X509_CRL_add1_ext_i2d: function (x: PX509_CRL; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get_ext_count: function (const x: PX509_REVOKED): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get_ext_by_NID: function (const x: PX509_REVOKED; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get_ext_by_OBJ: function (const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get_ext_by_critical: function (const x: PX509_REVOKED; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get_ext: function (const x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = nil;
  X509_REVOKED_delete_ext: function (x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = nil;
  X509_REVOKED_add_ext: function (x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_REVOKED_get_ext_d2i: function (const x: PX509_REVOKED; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = nil;
  X509_REVOKED_add1_ext_i2d: function (x: PX509_REVOKED; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  X509_EXTENSION_create_by_NID: function (ex: PPX509_EXTENSION; nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = nil;
  X509_EXTENSION_create_by_OBJ: function (ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = nil;
  X509_EXTENSION_set_object: function (ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_EXTENSION_set_critical: function (ex: PX509_EXTENSION; crit: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_EXTENSION_set_data: function (ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl = nil;
  X509_EXTENSION_get_object: function (ex: PX509_EXTENSION): PASN1_OBJECT; cdecl = nil;
  X509_EXTENSION_get_data: function (ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl = nil;
  X509_EXTENSION_get_critical: function (const ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl = nil;
  X509_ATTRIBUTE_create_by_NID: function (attr: PPX509_ATTRIBUTE; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  X509_ATTRIBUTE_create_by_OBJ: function (attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  X509_ATTRIBUTE_create_by_txt: function (attr: PPX509_ATTRIBUTE; const atrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  X509_ATTRIBUTE_set1_object: function (attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  X509_ATTRIBUTE_set1_data: function (attr: PX509_ATTRIBUTE; attrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_ATTRIBUTE_get0_data: function (attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; data: Pointer): Pointer; cdecl = nil;
  X509_ATTRIBUTE_count: function (const attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = nil;
  X509_ATTRIBUTE_get0_object: function (attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl = nil;
  X509_ATTRIBUTE_get0_type: function (attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT): PASN1_TYPE; cdecl = nil;
  EVP_PKEY_get_attr_count: function (const key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_attr_by_NID: function (const key: PEVP_PKEY; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_attr_by_OBJ: function (const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_attr: function (const key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  EVP_PKEY_delete_attr: function (key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  EVP_PKEY_add1_attr: function (key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_add1_attr_by_OBJ: function (key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_add1_attr_by_NID: function (key: PEVP_PKEY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_add1_attr_by_txt: function (key: PEVP_PKEY; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_verify_cert: function (ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_pbe_set0_algor: function (algor: PX509_ALGOR; alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_pbe_set: function (alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl = nil;
  PKCS5_pbe2_set: function (const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl = nil;
  PKCS5_pbe2_set_iv: function (const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; prf_nid: TOpenSSL_C_INT): PX509_ALGOR; cdecl = nil;
  PKCS5_pbe2_set_scrypt: function (const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64): PX509_ALGOR; cdecl = nil;
  PKCS5_pbkdf2_set: function (iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; prf_nid: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT): PX509_ALGOR; cdecl = nil;
  EVP_PKCS82PKEY: function (const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl = nil;
  EVP_PKEY2PKCS8: function (pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl = nil;
  PKCS8_pkey_set0: function (priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TOpenSSL_C_INT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS8_pkey_get0: function (const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = nil;
  PKCS8_pkey_add1_attr_by_NID: function (p8: PPKCS8_PRIV_KEY_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_PUBKEY_set0_param: function (pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_PUBKEY_get0_param: function (ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl = nil;
  X509_check_trust: function (x: PX509; id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_TRUST_get_count: function : TOpenSSL_C_INT; cdecl = nil;
  X509_TRUST_get0: function (idx: TOpenSSL_C_INT): PX509_TRUST; cdecl = nil;
  X509_TRUST_get_by_id: function (id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_TRUST_cleanup: procedure ; cdecl = nil;
  X509_TRUST_get_flags: function (const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl = nil;
  X509_TRUST_get0_name: function (const xp: PX509_TRUST): PAnsiChar; cdecl = nil;
  X509_TRUST_get_trust: function (const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl = nil;
  X509_NAME_hash_ex: function (const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  X509_NAME_hash: function (x: PX509_NAME): TOpenSSL_C_ULONG; cdecl = nil; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  X509_http_nbio_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  X509_CRL_http_nbio_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  X509_PUBKEY_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_pathlen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_getm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_INFO_get_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_INFO_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_signature_info_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_signature_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_trusted_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_serialNumber_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_notBefore_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_getm_notBefore_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_set1_notBefore_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_notAfter_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_getm_notAfter_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_set1_notAfter_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_signature_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_X509_PUBKEY_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_uids_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_tbs_sigalg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_pubkey_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_subject_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get0_signature_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_signature_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  i2d_re_X509_REQ_tbs_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get0_pubkey_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_X509_PUBKEY_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_set1_lastUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_set1_nextUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get0_lastUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get0_nextUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get_issuer_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get0_signature_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get_signature_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  i2d_re_X509_CRL_tbs_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REVOKED_get0_serialNumber_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REVOKED_get0_revocationDate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_hash_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  X509_aux_print_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_print_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_ENTRY_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_get0_der_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS5_pbe2_set_scrypt_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS8_pkey_add1_attr_by_NID_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_hash_ex_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}


implementation


//# define X509_NAME_hash(x) X509_NAME_hash_ex(x, NULL, NULL, NULL)

uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  X509_http_nbio: function (rctx: POCSP_REQ_CTX; pcert: PPX509): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  X509_CRL_http_nbio: function (rctx: POCSP_REQ_CTX; pcrl: PPX509_CRL): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  ASIdentifierChoice_inherit = 0;
  ASIdentifierChoice_asIdsOrRanges = 1;
  SHA_DIGEST_LENGTH = 20;

type
  PSTACK= type pointer;
  PSTACK_OF_X509_EXTENSION = PSTACK; 
  PX509_CINF = ^_X509_CINF;
  _X509_CINF = record
    version: PASN1_INTEGER;
    serialNumber: PASN1_INTEGER;
    signature: PX509_ALGOR;
    issuer: PX509_NAME;
    validity: PX509_VAL;
    subject: PX509_NAME;
    key: PX509_PUBKEY;
    issuerUID: PASN1_BIT_STRING; // [ 1 ] optional in v2
    subjectUID: PASN1_BIT_STRING; // [ 2 ] optional in v2
    extensions: PSTACK_OF_X509_EXTENSION;
    enc : ASN1_ENCODING;
  end;

  PSTACK_OF_ASIdOrRange = PSTACK;

  PSTACK_OF_DIST_POINT = PSTACK;
  PSTACK_OF_GENERAL_NAME = PSTACK;
  PSTACK_OF_IPAddressFamily = PSTACK;
  PASIdOrRanges = PSTACK_OF_ASIdOrRange;

  ASIdentifierChoice_union = record
  case byte of
   ASIdentifierChoice_inherit : (inherit : PASN1_NULL);
   ASIdentifierChoice_asIdsOrRanges : (asIdsOrRanges : PASIdOrRanges);
  end;

  PASIdentifierChoice = ^ASIdentifierChoice;
  ASIdentifierChoice = record
    _type : TOpenSSL_C_INT;
    u : ASIdentifierChoice_union;
  end;

  PASIdentifiers = ^ASIdentifiers;
  ASIdentifiers = record
    asnum : PASIdentifierChoice;
    rdi : PASIdentifierChoice;
  end;

  PX509_CERT_AUX = pointer;
  
   _PX509 = ^X509;

X509 = record
    cert_info: PX509_CINF;
    sig_alg : PX509_ALGOR;
    signature : PASN1_BIT_STRING;
    valid : TOpenSSL_C_INT;
    references : TOpenSSL_C_INT;
    name : PAnsiChar;
    ex_data : CRYPTO_EX_DATA;
    // These contain copies of various extension values
    ex_pathlen : TOpenSSL_C_LONG;
    ex_pcpathlen : TOpenSSL_C_LONG;
    ex_flags : TOpenSSL_C_ULONG;
    ex_kusage : TOpenSSL_C_ULONG;
    ex_xkusage : TOpenSSL_C_ULONG;
    ex_nscert : TOpenSSL_C_ULONG;
    skid : PASN1_OCTET_STRING;
    akid : PAUTHORITY_KEYID;
    policy_cache : PX509_POLICY_CACHE;
    crldp : PSTACK_OF_DIST_POINT;
    altname : PSTACK_OF_GENERAL_NAME;
    nc : PNAME_CONSTRAINTS;
    {$IFNDEF OPENSSL_NO_RFC3779}
    rfc3779_addr : PSTACK_OF_IPAddressFamily;
    rfc3779_asid : PASIdentifiers;
    {$ENDIF}
    {$IFNDEF OPENSSL_NO_SHA}
    sha1_hash : array [0..SHA_DIGEST_LENGTH-1] of AnsiChar;
    {$ENDIF}
    aux : PX509_CERT_AUX;
  end;   


{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG;

begin
  Result := X509_NAME_hash_ex(x,nil,nil,nil);
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl;

begin
  Result := X509_NAME_hash_ex(x,nil,nil,nil);
end;


procedure COMPAT_X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl;

begin
  sig := _PX509(x)^.signature;
  alg := _PX509(x)^.sig_alg;
end;



function COMPAT_X509_get0_notBefore(const x: PX509): PASN1_TIME; cdecl;

begin
  Result := _PX509(x)^.cert_info.validity.notBefore;
end;



function COMPAT_X509_get0_notAfter(const x: PX509): PASN1_TIME; cdecl;

begin
  Result := _PX509(x)^.cert_info.validity.notAfter;
end;



function COMPAT_X509_get_signature_type(const x: PX509): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_type(OBJ_obj2nid(_PX509(x)^.sig_alg^.algorithm));
end;









{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
procedure ERROR_X509_CRL_set_default_method(const meth: PX509_CRL_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_default_method');
end;

procedure ERROR_X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_METHOD_free');
end;

procedure ERROR_X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_meth_data');
end;

function ERROR_X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_meth_data');
end;

function ERROR_X509_verify_cert_error_string(n: TOpenSSL_C_LONG): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_verify_cert_error_string');
end;

function ERROR_X509_verify(a: PX509; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_verify');
end;

function ERROR_X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_verify');
end;

function ERROR_X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_verify');
end;

function ERROR_NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_verify');
end;

function ERROR_NETSCAPE_SPKI_b64_decode(const str: PAnsiChar; len: TOpenSSL_C_INT): PNETSCAPE_SPKI; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_b64_decode');
end;

function ERROR_NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_b64_encode');
end;

function ERROR_NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_get_pubkey');
end;

function ERROR_NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_set_pubkey');
end;

function ERROR_NETSCAPE_SPKI_print(out_: PBIO; spki: PNETSCAPE_SPKI): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_print');
end;

function ERROR_X509_signature_dump(bp: PBIO; const sig: PASN1_STRING; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_signature_dump');
end;

function ERROR_X509_signature_print(bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_signature_print');
end;

function ERROR_X509_sign(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_sign');
end;

function ERROR_X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_sign_ctx');
end;

function ERROR_X509_http_nbio(rctx: POCSP_REQ_CTX; pcert: PPX509): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_http_nbio');
end;

function ERROR_X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_sign');
end;

function ERROR_X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_sign_ctx');
end;

function ERROR_X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_sign');
end;

function ERROR_X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_sign_ctx');
end;

function ERROR_X509_CRL_http_nbio(rctx: POCSP_REQ_CTX; pcrl: PPX509_CRL): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_http_nbio');
end;

function ERROR_NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_sign');
end;

function ERROR_X509_pubkey_digest(const data: PX509; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_pubkey_digest');
end;

function ERROR_X509_digest(const data: PX509; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_digest');
end;

function ERROR_X509_CRL_digest(const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_digest');
end;

function ERROR_X509_REQ_digest(const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_digest');
end;

function ERROR_X509_NAME_digest(const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_digest');
end;

function ERROR_d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_bio');
end;

function ERROR_i2d_X509_bio(bp: PBIO; x509: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_bio');
end;

function ERROR_d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_CRL_bio');
end;

function ERROR_i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_CRL_bio');
end;

function ERROR_d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REQ_bio');
end;

function ERROR_i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REQ_bio');
end;

function ERROR_d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSAPrivateKey_bio');
end;

function ERROR_i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSAPrivateKey_bio');
end;

function ERROR_d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSAPublicKey_bio');
end;

function ERROR_i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSAPublicKey_bio');
end;

function ERROR_d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSA_PUBKEY_bio');
end;

function ERROR_i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSA_PUBKEY_bio');
end;

function ERROR_d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): DSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSA_PUBKEY_bio');
end;

function ERROR_i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSA_PUBKEY_bio');
end;

function ERROR_d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPrivateKey_bio');
end;

function ERROR_i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPrivateKey_bio');
end;

function ERROR_d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_EC_PUBKEY_bio');
end;

function ERROR_i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_EC_PUBKEY_bio');
end;

function ERROR_d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): EC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPrivateKey_bio');
end;

function ERROR_i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPrivateKey_bio');
end;

function ERROR_d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8_bio');
end;

function ERROR_i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8_bio');
end;

function ERROR_d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8_PRIV_KEY_INFO_bio');
end;

function ERROR_i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8_PRIV_KEY_INFO_bio');
end;

function ERROR_i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKeyInfo_bio');
end;

function ERROR_i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PrivateKey_bio');
end;

function ERROR_d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PrivateKey_bio');
end;

function ERROR_i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PUBKEY_bio');
end;

function ERROR_d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PUBKEY_bio');
end;

function ERROR_X509_dup(x509: PX509): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_dup');
end;

function ERROR_X509_ATTRIBUTE_dup(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_dup');
end;

function ERROR_X509_EXTENSION_dup(ex: PX509_EXTENSION): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_dup');
end;

function ERROR_X509_CRL_dup(crl: PX509_CRL): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_dup');
end;

function ERROR_X509_REVOKED_dup(rev: PX509_REVOKED): PX509_REVOKED; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_dup');
end;

function ERROR_X509_REQ_dup(req: PX509_REQ): PX509_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_dup');
end;

function ERROR_X509_ALGOR_dup(xn: PX509_ALGOR): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_dup');
end;

function ERROR_X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_set0');
end;

procedure ERROR_X509_ALGOR_get0(const paobj: PPASN1_OBJECT; pptype: POpenSSL_C_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_get0');
end;

procedure ERROR_X509_ALGOR_set_md(alg: PX509_ALGOR; const md: PEVP_MD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_set_md');
end;

function ERROR_X509_ALGOR_cmp(const a: PX509_ALGOR; const b: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_cmp');
end;

function ERROR_X509_NAME_dup(xn: PX509_NAME): PX509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_dup');
end;

function ERROR_X509_NAME_ENTRY_dup(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_dup');
end;

function ERROR_X509_cmp_time(const s: PASN1_TIME; t: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_cmp_time');
end;

function ERROR_X509_cmp_current_time(const s: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_cmp_current_time');
end;

function ERROR_X509_time_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_time_adj');
end;

function ERROR_X509_time_adj_ex(s: PASN1_TIME; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_time_adj_ex');
end;

function ERROR_X509_gmtime_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_gmtime_adj');
end;

function ERROR_X509_get_default_cert_area: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_area');
end;

function ERROR_X509_get_default_cert_dir: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_dir');
end;

function ERROR_X509_get_default_cert_file: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_file');
end;

function ERROR_X509_get_default_cert_dir_env: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_dir_env');
end;

function ERROR_X509_get_default_cert_file_env: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_file_env');
end;

function ERROR_X509_get_default_private_dir: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_private_dir');
end;

function ERROR_X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_to_X509_REQ');
end;

function ERROR_X509_REQ_to_X509(r: PX509_REQ; days: TOpenSSL_C_INT; pkey: PEVP_PKEY): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_to_X509');
end;

function ERROR_X509_ALGOR_new: PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_new');
end;

procedure ERROR_X509_ALGOR_free(v1: PX509_ALGOR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_free');
end;

function ERROR_d2i_X509_ALGOR(a: PPX509_ALGOR; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_ALGOR');
end;

function ERROR_i2d_X509_ALGOR(a: PX509_ALGOR; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_ALGOR');
end;

function ERROR_X509_VAL_new: PX509_VAL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VAL_new');
end;

procedure ERROR_X509_VAL_free(v1: PX509_VAL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VAL_free');
end;

function ERROR_d2i_X509_VAL(a: PPX509_VAL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_VAL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_VAL');
end;

function ERROR_i2d_X509_VAL(a: PX509_VAL; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_VAL');
end;

function ERROR_X509_PUBKEY_new: PX509_PUBKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_new');
end;

procedure ERROR_X509_PUBKEY_free(v1: PX509_PUBKEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_free');
end;

function ERROR_d2i_X509_PUBKEY(a: PPX509_PUBKEY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_PUBKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_PUBKEY');
end;

function ERROR_i2d_X509_PUBKEY(a: PX509_PUBKEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_PUBKEY');
end;

function ERROR_X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_set');
end;

function ERROR_X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_get0');
end;

function ERROR_X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_get');
end;

function ERROR_X509_get_pathlen(x: PX509): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_pathlen');
end;

function ERROR_i2d_PUBKEY(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PUBKEY');
end;

function ERROR_d2i_PUBKEY(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PUBKEY');
end;

function ERROR_i2d_RSA_PUBKEY(a: PRSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSA_PUBKEY');
end;

function ERROR_d2i_RSA_PUBKEY(a: PPRSA; const pp: PPByte; length: TOpenSSL_C_LONG): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSA_PUBKEY');
end;

function ERROR_i2d_DSA_PUBKEY(a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSA_PUBKEY');
end;

function ERROR_d2i_DSA_PUBKEY(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSA_PUBKEY');
end;

function ERROR_i2d_EC_PUBKEY(a: EC_KEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_EC_PUBKEY');
end;

function ERROR_d2i_EC_PUBKEY(a: PPEC_KEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_EC_PUBKEY');
end;

function ERROR_X509_SIG_new: PX509_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_new');
end;

procedure ERROR_X509_SIG_free(v1: PX509_SIG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_free');
end;

function ERROR_d2i_X509_SIG(a: PPX509_SIG; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_SIG');
end;

function ERROR_i2d_X509_SIG(a: PX509_SIG; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_SIG');
end;

procedure ERROR_X509_SIG_get0(const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_get0');
end;

procedure ERROR_X509_SIG_getm(sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_getm');
end;

function ERROR_X509_REQ_INFO_new: PX509_REQ_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_INFO_new');
end;

procedure ERROR_X509_REQ_INFO_free(v1: PX509_REQ_INFO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_INFO_free');
end;

function ERROR_d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REQ_INFO');
end;

function ERROR_i2d_X509_REQ_INFO(a: PX509_REQ_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REQ_INFO');
end;

function ERROR_X509_REQ_new: PX509_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_new');
end;

procedure ERROR_X509_REQ_free(v1: PX509_REQ); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_free');
end;

function ERROR_d2i_X509_REQ(a: PPX509_REQ; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REQ');
end;

function ERROR_i2d_X509_REQ(a: PX509_REQ; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REQ');
end;

function ERROR_X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_new');
end;

procedure ERROR_X509_ATTRIBUTE_free(v1: PX509_ATTRIBUTE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_free');
end;

function ERROR_d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_ATTRIBUTE');
end;

function ERROR_i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_ATTRIBUTE');
end;

function ERROR_X509_ATTRIBUTE_create(nid: TOpenSSL_C_INT; trtype: TOpenSSL_C_INT; value: Pointer): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create');
end;

function ERROR_X509_EXTENSION_new: PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_new');
end;

procedure ERROR_X509_EXTENSION_free(v1: PX509_EXTENSION); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_free');
end;

function ERROR_d2i_X509_EXTENSION(a: PPX509_EXTENSION; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_EXTENSION');
end;

function ERROR_i2d_X509_EXTENSION(a: PX509_EXTENSION; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_EXTENSION');
end;

function ERROR_X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_new');
end;

procedure ERROR_X509_NAME_ENTRY_free(v1: PX509_NAME_ENTRY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_free');
end;

function ERROR_d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_NAME_ENTRY');
end;

function ERROR_i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_NAME_ENTRY');
end;

function ERROR_X509_NAME_new: PX509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_new');
end;

procedure ERROR_X509_NAME_free(v1: PX509_NAME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_free');
end;

function ERROR_d2i_X509_NAME(a: PPX509_NAME; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_NAME');
end;

function ERROR_i2d_X509_NAME(a: PX509_NAME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_NAME');
end;

function ERROR_X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_set');
end;

function ERROR_X509_new: PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_new');
end;

procedure ERROR_X509_free(v1: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_free');
end;

function ERROR_d2i_X509(a: PPX509; const in_: PPByte; len: TOpenSSL_C_LONG): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509');
end;

function ERROR_i2d_X509(a: PX509; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509');
end;

function ERROR_X509_set_ex_data(r: PX509; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_ex_data');
end;

function ERROR_X509_get_ex_data(r: PX509; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ex_data');
end;

function ERROR_i2d_X509_AUX(a: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_AUX');
end;

function ERROR_d2i_X509_AUX(a: PPX509; const pp: PPByte; length: TOpenSSL_C_LONG): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_AUX');
end;

function ERROR_i2d_re_X509_tbs(x: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_re_X509_tbs');
end;

function ERROR_X509_SIG_INFO_get(const siginf: PX509_SIG_INFO; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_INFO_get');
end;

procedure ERROR_X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TOpenSSL_C_INT; pknid: TOpenSSL_C_INT; secbits: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT32); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_INFO_set');
end;

function ERROR_X509_get_signature_info(x: PX509; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_signature_info');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_signature');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_get_signature_nid(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_signature_nid');
end;

function ERROR_X509_trusted(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_trusted');
end;

function ERROR_X509_alias_set1(x: PX509; const name: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_alias_set1');
end;

function ERROR_X509_keyid_set1(x: PX509; const id: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_keyid_set1');
end;

function ERROR_X509_alias_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_alias_get0');
end;

function ERROR_X509_keyid_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_keyid_get0');
end;

function ERROR_X509_TRUST_set(t: POpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_set');
end;

function ERROR_X509_add1_trust_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add1_trust_object');
end;

function ERROR_X509_add1_reject_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add1_reject_object');
end;

procedure ERROR_X509_trust_clear(x: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_trust_clear');
end;

procedure ERROR_X509_reject_clear(x: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_reject_clear');
end;

function ERROR_X509_REVOKED_new: PX509_REVOKED; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_new');
end;

procedure ERROR_X509_REVOKED_free(v1: PX509_REVOKED); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_free');
end;

function ERROR_d2i_X509_REVOKED(a: PPX509_REVOKED; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REVOKED; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REVOKED');
end;

function ERROR_i2d_X509_REVOKED(a: PX509_REVOKED; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REVOKED');
end;

function ERROR_X509_CRL_INFO_new: PX509_CRL_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_INFO_new');
end;

procedure ERROR_X509_CRL_INFO_free(v1: PX509_CRL_INFO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_INFO_free');
end;

function ERROR_d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_CRL_INFO');
end;

function ERROR_i2d_X509_CRL_INFO(a: PX509_CRL_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_CRL_INFO');
end;

function ERROR_X509_CRL_new: PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_new');
end;

procedure ERROR_X509_CRL_free(v1: PX509_CRL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_free');
end;

function ERROR_d2i_X509_CRL(a: PPX509_CRL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_CRL');
end;

function ERROR_i2d_X509_CRL(a: PX509_CRL; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_CRL');
end;

function ERROR_X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_add0_revoked');
end;

function ERROR_X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_by_serial');
end;

function ERROR_X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_by_cert');
end;

function ERROR_X509_PKEY_new: PX509_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PKEY_new');
end;

procedure ERROR_X509_PKEY_free(a: PX509_PKEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PKEY_free');
end;

function ERROR_X509_INFO_new: PX509_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_INFO_new');
end;

procedure ERROR_X509_INFO_free(a: PX509_INFO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_INFO_free');
end;

function ERROR_X509_NAME_oneline(const a: PX509_NAME; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_oneline');
end;

function ERROR_ASN1_item_digest(const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_digest');
end;

function ERROR_ASN1_item_verify(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_verify');
end;

function ERROR_ASN1_item_sign(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_sign');
end;

function ERROR_ASN1_item_sign_ctx(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_sign_ctx');
end;

function ERROR_X509_get_version(const x: PX509): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_version');
end;

function ERROR_X509_set_version(x: PX509; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_version');
end;

function ERROR_X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_serialNumber');
end;

function ERROR_X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_serialNumber');
end;

function ERROR_X509_get0_serialNumber(const x: PX509): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_serialNumber');
end;

function ERROR_X509_set_issuer_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_issuer_name');
end;

function ERROR_X509_get_issuer_name(const a: PX509): PX509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_issuer_name');
end;

function ERROR_X509_set_subject_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_subject_name');
end;

function ERROR_X509_get_subject_name(const a: PX509): PX509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_subject_name');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_get0_notBefore(const x: PX509): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_notBefore');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_getm_notBefore(const x: PX509): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_getm_notBefore');
end;

function ERROR_X509_set1_notBefore(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set1_notBefore');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_get0_notAfter(const x: PX509): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_notAfter');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_getm_notAfter(const x: PX509): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_getm_notAfter');
end;

function ERROR_X509_set1_notAfter(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set1_notAfter');
end;

function ERROR_X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_pubkey');
end;

function ERROR_X509_up_ref(x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_up_ref');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_get_signature_type(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_signature_type');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_get_X509_PUBKEY(const x: PX509): PX509_PUBKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_X509_PUBKEY');
end;

procedure ERROR_X509_get0_uids(const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_uids');
end;

function ERROR_X509_get0_tbs_sigalg(const x: PX509): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_tbs_sigalg');
end;

function ERROR_X509_get0_pubkey(const x: PX509): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_pubkey');
end;

function ERROR_X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_pubkey');
end;

function ERROR_X509_get0_pubkey_bitstr(const x: PX509): PASN1_BIT_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_pubkey_bitstr');
end;

function ERROR_X509_certificate_type(const x: PX509; const pubkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_certificate_type');
end;

function ERROR_X509_REQ_get_version(const req: PX509_REQ): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_version');
end;

function ERROR_X509_REQ_set_version(x: PX509_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_version');
end;

function ERROR_X509_REQ_get_subject_name(const req: PX509_REQ): PX509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_subject_name');
end;

function ERROR_X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_subject_name');
end;

procedure ERROR_X509_REQ_get0_signature(const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get0_signature');
end;

function ERROR_X509_REQ_get_signature_nid(const req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_signature_nid');
end;

function ERROR_i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_re_X509_REQ_tbs');
end;

function ERROR_X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_pubkey');
end;

function ERROR_X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_pubkey');
end;

function ERROR_X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get0_pubkey');
end;

function ERROR_X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_X509_PUBKEY');
end;

function ERROR_X509_REQ_extension_nid(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_extension_nid');
end;

function ERROR_X509_REQ_get_extension_nids: POpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_extension_nids');
end;

procedure ERROR_X509_REQ_set_extension_nids(nids: POpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_extension_nids');
end;

function ERROR_X509_REQ_get_attr_count(const req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr_count');
end;

function ERROR_X509_REQ_get_attr_by_NID(const req: PX509_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr_by_NID');
end;

function ERROR_X509_REQ_get_attr_by_OBJ(const req: PX509_REQ; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr_by_OBJ');
end;

function ERROR_X509_REQ_get_attr(const req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr');
end;

function ERROR_X509_REQ_delete_attr(req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_delete_attr');
end;

function ERROR_X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr');
end;

function ERROR_X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr_by_OBJ');
end;

function ERROR_X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr_by_NID');
end;

function ERROR_X509_REQ_add1_attr_by_txt(req: PX509_REQ; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr_by_txt');
end;

function ERROR_X509_CRL_set_version(x: PX509_CRL; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_version');
end;

function ERROR_X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_issuer_name');
end;

function ERROR_X509_CRL_set1_lastUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set1_lastUpdate');
end;

function ERROR_X509_CRL_set1_nextUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set1_nextUpdate');
end;

function ERROR_X509_CRL_sort(crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_sort');
end;

function ERROR_X509_CRL_up_ref(crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_up_ref');
end;

function ERROR_X509_CRL_get_version(const crl: PX509_CRL): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_version');
end;

function ERROR_X509_CRL_get0_lastUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_lastUpdate');
end;

function ERROR_X509_CRL_get0_nextUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_nextUpdate');
end;

function ERROR_X509_CRL_get_issuer(const crl: PX509_CRL): PX509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_issuer');
end;

procedure ERROR_X509_CRL_get0_signature(const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_signature');
end;

function ERROR_X509_CRL_get_signature_nid(const crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_signature_nid');
end;

function ERROR_i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_re_X509_CRL_tbs');
end;

function ERROR_X509_REVOKED_get0_serialNumber(const x: PX509_REVOKED): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get0_serialNumber');
end;

function ERROR_X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_set_serialNumber');
end;

function ERROR_X509_REVOKED_get0_revocationDate(const x: PX509_REVOKED): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get0_revocationDate');
end;

function ERROR_X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_set_revocationDate');
end;

function ERROR_X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_diff');
end;

function ERROR_X509_REQ_check_private_key(x509: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_check_private_key');
end;

function ERROR_X509_check_private_key(const x509: PX509; const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_private_key');
end;

function ERROR_X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_check_suiteb');
end;

function ERROR_X509_issuer_and_serial_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_and_serial_cmp');
end;

function ERROR_X509_issuer_and_serial_hash(a: PX509): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_and_serial_hash');
end;

function ERROR_X509_issuer_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_name_cmp');
end;

function ERROR_X509_issuer_name_hash(a: PX509): TOpenSSL_C_uLONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_name_hash');
end;

function ERROR_X509_subject_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_subject_name_cmp');
end;

function ERROR_X509_subject_name_hash(x: PX509): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_subject_name_hash');
end;

function ERROR_X509_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_cmp');
end;

function ERROR_X509_NAME_cmp(const a: PX509_NAME; const b: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_cmp');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_hash');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_X509_NAME_hash_old(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_hash_old');
end;

function ERROR_X509_CRL_cmp(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_cmp');
end;

function ERROR_X509_CRL_match(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_match');
end;

function ERROR_X509_aux_print(out_: PBIO; x: PX509; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_aux_print');
end;

function ERROR_X509_NAME_print(bp: PBIO; const name: PX509_NAME; obase: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_print');
end;

function ERROR_X509_NAME_print_ex(out_: PBIO; const nm: PX509_NAME; indent: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_print_ex');
end;

function ERROR_X509_print_ex(bp: PBIO; x: PX509; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_print_ex');
end;

function ERROR_X509_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_print');
end;

function ERROR_X509_ocspid_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ocspid_print');
end;

function ERROR_X509_CRL_print_ex(out_: PBIO; x: PX509_CRL; nmflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_print_ex');
end;

function ERROR_X509_CRL_print(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_print');
end;

function ERROR_X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_print_ex');
end;

function ERROR_X509_REQ_print(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_print');
end;

function ERROR_X509_NAME_entry_count(const name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_entry_count');
end;

function ERROR_X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_text_by_NID');
end;

function ERROR_X509_NAME_get_text_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_text_by_OBJ');
end;

function ERROR_X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_index_by_NID');
end;

function ERROR_X509_NAME_get_index_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_index_by_OBJ');
end;

function ERROR_X509_NAME_get_entry(const name: PX509_NAME; loc: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_entry');
end;

function ERROR_X509_NAME_delete_entry(name: PX509_NAME; loc: TOpenSSL_C_INT): pX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_delete_entry');
end;

function ERROR_X509_NAME_add_entry(name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry');
end;

function ERROR_X509_NAME_add_entry_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry_by_OBJ');
end;

function ERROR_X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry_by_NID');
end;

function ERROR_X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_create_by_txt');
end;

function ERROR_X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_create_by_NID');
end;

function ERROR_X509_NAME_add_entry_by_txt(name: PX509_NAME; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry_by_txt');
end;

function ERROR_X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_create_by_OBJ');
end;

function ERROR_X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_set_object');
end;

function ERROR_X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_set_data');
end;

function ERROR_X509_NAME_ENTRY_get_object(const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_get_object');
end;

function ERROR_X509_NAME_ENTRY_get_data(const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_get_data');
end;

function ERROR_X509_NAME_ENTRY_set(const ne: PX509_NAME_ENTRY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_set');
end;

function ERROR_X509_NAME_get0_der(nm: PX509_NAME; const pder: PPByte; pderlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get0_der');
end;

function ERROR_X509_get_ext_count(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_count');
end;

function ERROR_X509_get_ext_by_NID(const x: PX509; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_by_NID');
end;

function ERROR_X509_get_ext_by_OBJ(const x: PX509; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_by_OBJ');
end;

function ERROR_X509_get_ext_by_critical(const x: PX509; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_by_critical');
end;

function ERROR_X509_get_ext(const x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext');
end;

function ERROR_X509_delete_ext(x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_delete_ext');
end;

function ERROR_X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add_ext');
end;

function ERROR_X509_get_ext_d2i(const x: PX509; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_d2i');
end;

function ERROR_X509_add1_ext_i2d(x: PX509; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add1_ext_i2d');
end;

function ERROR_X509_CRL_get_ext_count(const x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_count');
end;

function ERROR_X509_CRL_get_ext_by_NID(const x: PX509_CRL; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_by_NID');
end;

function ERROR_X509_CRL_get_ext_by_OBJ(const x: X509_CRL; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_by_OBJ');
end;

function ERROR_X509_CRL_get_ext_by_critical(const x: PX509_CRL; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_by_critical');
end;

function ERROR_X509_CRL_get_ext(const x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext');
end;

function ERROR_X509_CRL_delete_ext(x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_delete_ext');
end;

function ERROR_X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_add_ext');
end;

function ERROR_X509_CRL_get_ext_d2i(const x: PX509_CRL; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_d2i');
end;

function ERROR_X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_add1_ext_i2d');
end;

function ERROR_X509_REVOKED_get_ext_count(const x: PX509_REVOKED): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_count');
end;

function ERROR_X509_REVOKED_get_ext_by_NID(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_by_NID');
end;

function ERROR_X509_REVOKED_get_ext_by_OBJ(const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_by_OBJ');
end;

function ERROR_X509_REVOKED_get_ext_by_critical(const x: PX509_REVOKED; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_by_critical');
end;

function ERROR_X509_REVOKED_get_ext(const x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext');
end;

function ERROR_X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_delete_ext');
end;

function ERROR_X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_add_ext');
end;

function ERROR_X509_REVOKED_get_ext_d2i(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_d2i');
end;

function ERROR_X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_add1_ext_i2d');
end;

function ERROR_X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_create_by_NID');
end;

function ERROR_X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_create_by_OBJ');
end;

function ERROR_X509_EXTENSION_set_object(ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_set_object');
end;

function ERROR_X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_set_critical');
end;

function ERROR_X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_set_data');
end;

function ERROR_X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_get_object');
end;

function ERROR_X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_get_data');
end;

function ERROR_X509_EXTENSION_get_critical(const ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_get_critical');
end;

function ERROR_X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create_by_NID');
end;

function ERROR_X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create_by_OBJ');
end;

function ERROR_X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; const atrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create_by_txt');
end;

function ERROR_X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_set1_object');
end;

function ERROR_X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_set1_data');
end;

function ERROR_X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; data: Pointer): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_get0_data');
end;

function ERROR_X509_ATTRIBUTE_count(const attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_count');
end;

function ERROR_X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_get0_object');
end;

function ERROR_X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_get0_type');
end;

function ERROR_EVP_PKEY_get_attr_count(const key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr_count');
end;

function ERROR_EVP_PKEY_get_attr_by_NID(const key: PEVP_PKEY; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr_by_NID');
end;

function ERROR_EVP_PKEY_get_attr_by_OBJ(const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr_by_OBJ');
end;

function ERROR_EVP_PKEY_get_attr(const key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr');
end;

function ERROR_EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_delete_attr');
end;

function ERROR_EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr');
end;

function ERROR_EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr_by_OBJ');
end;

function ERROR_EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr_by_NID');
end;

function ERROR_EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr_by_txt');
end;

function ERROR_X509_verify_cert(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_verify_cert');
end;

function ERROR_PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe_set0_algor');
end;

function ERROR_PKCS5_pbe_set(alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe_set');
end;

function ERROR_PKCS5_pbe2_set(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe2_set');
end;

function ERROR_PKCS5_pbe2_set_iv(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; prf_nid: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe2_set_iv');
end;

function ERROR_PKCS5_pbe2_set_scrypt(const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe2_set_scrypt');
end;

function ERROR_PKCS5_pbkdf2_set(iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; prf_nid: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbkdf2_set');
end;

function ERROR_EVP_PKCS82PKEY(const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKCS82PKEY');
end;

function ERROR_EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY2PKCS8');
end;

function ERROR_PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TOpenSSL_C_INT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_pkey_set0');
end;

function ERROR_PKCS8_pkey_get0(const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_pkey_get0');
end;

function ERROR_PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_pkey_add1_attr_by_NID');
end;

function ERROR_X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_set0_param');
end;

function ERROR_X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_get0_param');
end;

function ERROR_X509_check_trust(x: PX509; id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_trust');
end;

function ERROR_X509_TRUST_get_count: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_count');
end;

function ERROR_X509_TRUST_get0(idx: TOpenSSL_C_INT): PX509_TRUST; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get0');
end;

function ERROR_X509_TRUST_get_by_id(id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_by_id');
end;

procedure ERROR_X509_TRUST_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_cleanup');
end;

function ERROR_X509_TRUST_get_flags(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_flags');
end;

function ERROR_X509_TRUST_get0_name(const xp: PX509_TRUST): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get0_name');
end;

function ERROR_X509_TRUST_get_trust(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_trust');
end;

function ERROR_X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_hash_ex');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  X509_CRL_set_default_method := LoadLibCryptoFunction('X509_CRL_set_default_method');
  FuncLoadError := not assigned(X509_CRL_set_default_method);
  if FuncLoadError then
  begin
    X509_CRL_set_default_method :=  @ERROR_X509_CRL_set_default_method;
  end;

  X509_CRL_METHOD_free := LoadLibCryptoFunction('X509_CRL_METHOD_free');
  FuncLoadError := not assigned(X509_CRL_METHOD_free);
  if FuncLoadError then
  begin
    X509_CRL_METHOD_free :=  @ERROR_X509_CRL_METHOD_free;
  end;

  X509_CRL_set_meth_data := LoadLibCryptoFunction('X509_CRL_set_meth_data');
  FuncLoadError := not assigned(X509_CRL_set_meth_data);
  if FuncLoadError then
  begin
    X509_CRL_set_meth_data :=  @ERROR_X509_CRL_set_meth_data;
  end;

  X509_CRL_get_meth_data := LoadLibCryptoFunction('X509_CRL_get_meth_data');
  FuncLoadError := not assigned(X509_CRL_get_meth_data);
  if FuncLoadError then
  begin
    X509_CRL_get_meth_data :=  @ERROR_X509_CRL_get_meth_data;
  end;

  X509_verify_cert_error_string := LoadLibCryptoFunction('X509_verify_cert_error_string');
  FuncLoadError := not assigned(X509_verify_cert_error_string);
  if FuncLoadError then
  begin
    X509_verify_cert_error_string :=  @ERROR_X509_verify_cert_error_string;
  end;

  X509_verify := LoadLibCryptoFunction('X509_verify');
  FuncLoadError := not assigned(X509_verify);
  if FuncLoadError then
  begin
    X509_verify :=  @ERROR_X509_verify;
  end;

  X509_REQ_verify := LoadLibCryptoFunction('X509_REQ_verify');
  FuncLoadError := not assigned(X509_REQ_verify);
  if FuncLoadError then
  begin
    X509_REQ_verify :=  @ERROR_X509_REQ_verify;
  end;

  X509_CRL_verify := LoadLibCryptoFunction('X509_CRL_verify');
  FuncLoadError := not assigned(X509_CRL_verify);
  if FuncLoadError then
  begin
    X509_CRL_verify :=  @ERROR_X509_CRL_verify;
  end;

  NETSCAPE_SPKI_verify := LoadLibCryptoFunction('NETSCAPE_SPKI_verify');
  FuncLoadError := not assigned(NETSCAPE_SPKI_verify);
  if FuncLoadError then
  begin
    NETSCAPE_SPKI_verify :=  @ERROR_NETSCAPE_SPKI_verify;
  end;

  NETSCAPE_SPKI_b64_decode := LoadLibCryptoFunction('NETSCAPE_SPKI_b64_decode');
  FuncLoadError := not assigned(NETSCAPE_SPKI_b64_decode);
  if FuncLoadError then
  begin
    NETSCAPE_SPKI_b64_decode :=  @ERROR_NETSCAPE_SPKI_b64_decode;
  end;

  NETSCAPE_SPKI_b64_encode := LoadLibCryptoFunction('NETSCAPE_SPKI_b64_encode');
  FuncLoadError := not assigned(NETSCAPE_SPKI_b64_encode);
  if FuncLoadError then
  begin
    NETSCAPE_SPKI_b64_encode :=  @ERROR_NETSCAPE_SPKI_b64_encode;
  end;

  NETSCAPE_SPKI_get_pubkey := LoadLibCryptoFunction('NETSCAPE_SPKI_get_pubkey');
  FuncLoadError := not assigned(NETSCAPE_SPKI_get_pubkey);
  if FuncLoadError then
  begin
    NETSCAPE_SPKI_get_pubkey :=  @ERROR_NETSCAPE_SPKI_get_pubkey;
  end;

  NETSCAPE_SPKI_set_pubkey := LoadLibCryptoFunction('NETSCAPE_SPKI_set_pubkey');
  FuncLoadError := not assigned(NETSCAPE_SPKI_set_pubkey);
  if FuncLoadError then
  begin
    NETSCAPE_SPKI_set_pubkey :=  @ERROR_NETSCAPE_SPKI_set_pubkey;
  end;

  NETSCAPE_SPKI_print := LoadLibCryptoFunction('NETSCAPE_SPKI_print');
  FuncLoadError := not assigned(NETSCAPE_SPKI_print);
  if FuncLoadError then
  begin
    NETSCAPE_SPKI_print :=  @ERROR_NETSCAPE_SPKI_print;
  end;

  X509_signature_dump := LoadLibCryptoFunction('X509_signature_dump');
  FuncLoadError := not assigned(X509_signature_dump);
  if FuncLoadError then
  begin
    X509_signature_dump :=  @ERROR_X509_signature_dump;
  end;

  X509_signature_print := LoadLibCryptoFunction('X509_signature_print');
  FuncLoadError := not assigned(X509_signature_print);
  if FuncLoadError then
  begin
    X509_signature_print :=  @ERROR_X509_signature_print;
  end;

  X509_sign := LoadLibCryptoFunction('X509_sign');
  FuncLoadError := not assigned(X509_sign);
  if FuncLoadError then
  begin
    X509_sign :=  @ERROR_X509_sign;
  end;

  X509_sign_ctx := LoadLibCryptoFunction('X509_sign_ctx');
  FuncLoadError := not assigned(X509_sign_ctx);
  if FuncLoadError then
  begin
    X509_sign_ctx :=  @ERROR_X509_sign_ctx;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_http_nbio := LoadLibCryptoFunction('X509_http_nbio');
  FuncLoadError := not assigned(X509_http_nbio);
  if FuncLoadError then
  begin
    if X509_http_nbio_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('X509_http_nbio');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_REQ_sign := LoadLibCryptoFunction('X509_REQ_sign');
  FuncLoadError := not assigned(X509_REQ_sign);
  if FuncLoadError then
  begin
    X509_REQ_sign :=  @ERROR_X509_REQ_sign;
  end;

  X509_REQ_sign_ctx := LoadLibCryptoFunction('X509_REQ_sign_ctx');
  FuncLoadError := not assigned(X509_REQ_sign_ctx);
  if FuncLoadError then
  begin
    X509_REQ_sign_ctx :=  @ERROR_X509_REQ_sign_ctx;
  end;

  X509_CRL_sign := LoadLibCryptoFunction('X509_CRL_sign');
  FuncLoadError := not assigned(X509_CRL_sign);
  if FuncLoadError then
  begin
    X509_CRL_sign :=  @ERROR_X509_CRL_sign;
  end;

  X509_CRL_sign_ctx := LoadLibCryptoFunction('X509_CRL_sign_ctx');
  FuncLoadError := not assigned(X509_CRL_sign_ctx);
  if FuncLoadError then
  begin
    X509_CRL_sign_ctx :=  @ERROR_X509_CRL_sign_ctx;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_CRL_http_nbio := LoadLibCryptoFunction('X509_CRL_http_nbio');
  FuncLoadError := not assigned(X509_CRL_http_nbio);
  if FuncLoadError then
  begin
    if X509_CRL_http_nbio_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('X509_CRL_http_nbio');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  NETSCAPE_SPKI_sign := LoadLibCryptoFunction('NETSCAPE_SPKI_sign');
  FuncLoadError := not assigned(NETSCAPE_SPKI_sign);
  if FuncLoadError then
  begin
    NETSCAPE_SPKI_sign :=  @ERROR_NETSCAPE_SPKI_sign;
  end;

  X509_pubkey_digest := LoadLibCryptoFunction('X509_pubkey_digest');
  FuncLoadError := not assigned(X509_pubkey_digest);
  if FuncLoadError then
  begin
    X509_pubkey_digest :=  @ERROR_X509_pubkey_digest;
  end;

  X509_digest := LoadLibCryptoFunction('X509_digest');
  FuncLoadError := not assigned(X509_digest);
  if FuncLoadError then
  begin
    X509_digest :=  @ERROR_X509_digest;
  end;

  X509_CRL_digest := LoadLibCryptoFunction('X509_CRL_digest');
  FuncLoadError := not assigned(X509_CRL_digest);
  if FuncLoadError then
  begin
    X509_CRL_digest :=  @ERROR_X509_CRL_digest;
  end;

  X509_REQ_digest := LoadLibCryptoFunction('X509_REQ_digest');
  FuncLoadError := not assigned(X509_REQ_digest);
  if FuncLoadError then
  begin
    X509_REQ_digest :=  @ERROR_X509_REQ_digest;
  end;

  X509_NAME_digest := LoadLibCryptoFunction('X509_NAME_digest');
  FuncLoadError := not assigned(X509_NAME_digest);
  if FuncLoadError then
  begin
    X509_NAME_digest :=  @ERROR_X509_NAME_digest;
  end;

  d2i_X509_bio := LoadLibCryptoFunction('d2i_X509_bio');
  FuncLoadError := not assigned(d2i_X509_bio);
  if FuncLoadError then
  begin
    d2i_X509_bio :=  @ERROR_d2i_X509_bio;
  end;

  i2d_X509_bio := LoadLibCryptoFunction('i2d_X509_bio');
  FuncLoadError := not assigned(i2d_X509_bio);
  if FuncLoadError then
  begin
    i2d_X509_bio :=  @ERROR_i2d_X509_bio;
  end;

  d2i_X509_CRL_bio := LoadLibCryptoFunction('d2i_X509_CRL_bio');
  FuncLoadError := not assigned(d2i_X509_CRL_bio);
  if FuncLoadError then
  begin
    d2i_X509_CRL_bio :=  @ERROR_d2i_X509_CRL_bio;
  end;

  i2d_X509_CRL_bio := LoadLibCryptoFunction('i2d_X509_CRL_bio');
  FuncLoadError := not assigned(i2d_X509_CRL_bio);
  if FuncLoadError then
  begin
    i2d_X509_CRL_bio :=  @ERROR_i2d_X509_CRL_bio;
  end;

  d2i_X509_REQ_bio := LoadLibCryptoFunction('d2i_X509_REQ_bio');
  FuncLoadError := not assigned(d2i_X509_REQ_bio);
  if FuncLoadError then
  begin
    d2i_X509_REQ_bio :=  @ERROR_d2i_X509_REQ_bio;
  end;

  i2d_X509_REQ_bio := LoadLibCryptoFunction('i2d_X509_REQ_bio');
  FuncLoadError := not assigned(i2d_X509_REQ_bio);
  if FuncLoadError then
  begin
    i2d_X509_REQ_bio :=  @ERROR_i2d_X509_REQ_bio;
  end;

  d2i_RSAPrivateKey_bio := LoadLibCryptoFunction('d2i_RSAPrivateKey_bio');
  FuncLoadError := not assigned(d2i_RSAPrivateKey_bio);
  if FuncLoadError then
  begin
    d2i_RSAPrivateKey_bio :=  @ERROR_d2i_RSAPrivateKey_bio;
  end;

  i2d_RSAPrivateKey_bio := LoadLibCryptoFunction('i2d_RSAPrivateKey_bio');
  FuncLoadError := not assigned(i2d_RSAPrivateKey_bio);
  if FuncLoadError then
  begin
    i2d_RSAPrivateKey_bio :=  @ERROR_i2d_RSAPrivateKey_bio;
  end;

  d2i_RSAPublicKey_bio := LoadLibCryptoFunction('d2i_RSAPublicKey_bio');
  FuncLoadError := not assigned(d2i_RSAPublicKey_bio);
  if FuncLoadError then
  begin
    d2i_RSAPublicKey_bio :=  @ERROR_d2i_RSAPublicKey_bio;
  end;

  i2d_RSAPublicKey_bio := LoadLibCryptoFunction('i2d_RSAPublicKey_bio');
  FuncLoadError := not assigned(i2d_RSAPublicKey_bio);
  if FuncLoadError then
  begin
    i2d_RSAPublicKey_bio :=  @ERROR_i2d_RSAPublicKey_bio;
  end;

  d2i_RSA_PUBKEY_bio := LoadLibCryptoFunction('d2i_RSA_PUBKEY_bio');
  FuncLoadError := not assigned(d2i_RSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    d2i_RSA_PUBKEY_bio :=  @ERROR_d2i_RSA_PUBKEY_bio;
  end;

  i2d_RSA_PUBKEY_bio := LoadLibCryptoFunction('i2d_RSA_PUBKEY_bio');
  FuncLoadError := not assigned(i2d_RSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    i2d_RSA_PUBKEY_bio :=  @ERROR_i2d_RSA_PUBKEY_bio;
  end;

  d2i_DSA_PUBKEY_bio := LoadLibCryptoFunction('d2i_DSA_PUBKEY_bio');
  FuncLoadError := not assigned(d2i_DSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    d2i_DSA_PUBKEY_bio :=  @ERROR_d2i_DSA_PUBKEY_bio;
  end;

  i2d_DSA_PUBKEY_bio := LoadLibCryptoFunction('i2d_DSA_PUBKEY_bio');
  FuncLoadError := not assigned(i2d_DSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    i2d_DSA_PUBKEY_bio :=  @ERROR_i2d_DSA_PUBKEY_bio;
  end;

  d2i_DSAPrivateKey_bio := LoadLibCryptoFunction('d2i_DSAPrivateKey_bio');
  FuncLoadError := not assigned(d2i_DSAPrivateKey_bio);
  if FuncLoadError then
  begin
    d2i_DSAPrivateKey_bio :=  @ERROR_d2i_DSAPrivateKey_bio;
  end;

  i2d_DSAPrivateKey_bio := LoadLibCryptoFunction('i2d_DSAPrivateKey_bio');
  FuncLoadError := not assigned(i2d_DSAPrivateKey_bio);
  if FuncLoadError then
  begin
    i2d_DSAPrivateKey_bio :=  @ERROR_i2d_DSAPrivateKey_bio;
  end;

  d2i_EC_PUBKEY_bio := LoadLibCryptoFunction('d2i_EC_PUBKEY_bio');
  FuncLoadError := not assigned(d2i_EC_PUBKEY_bio);
  if FuncLoadError then
  begin
    d2i_EC_PUBKEY_bio :=  @ERROR_d2i_EC_PUBKEY_bio;
  end;

  i2d_EC_PUBKEY_bio := LoadLibCryptoFunction('i2d_EC_PUBKEY_bio');
  FuncLoadError := not assigned(i2d_EC_PUBKEY_bio);
  if FuncLoadError then
  begin
    i2d_EC_PUBKEY_bio :=  @ERROR_i2d_EC_PUBKEY_bio;
  end;

  d2i_ECPrivateKey_bio := LoadLibCryptoFunction('d2i_ECPrivateKey_bio');
  FuncLoadError := not assigned(d2i_ECPrivateKey_bio);
  if FuncLoadError then
  begin
    d2i_ECPrivateKey_bio :=  @ERROR_d2i_ECPrivateKey_bio;
  end;

  i2d_ECPrivateKey_bio := LoadLibCryptoFunction('i2d_ECPrivateKey_bio');
  FuncLoadError := not assigned(i2d_ECPrivateKey_bio);
  if FuncLoadError then
  begin
    i2d_ECPrivateKey_bio :=  @ERROR_i2d_ECPrivateKey_bio;
  end;

  d2i_PKCS8_bio := LoadLibCryptoFunction('d2i_PKCS8_bio');
  FuncLoadError := not assigned(d2i_PKCS8_bio);
  if FuncLoadError then
  begin
    d2i_PKCS8_bio :=  @ERROR_d2i_PKCS8_bio;
  end;

  i2d_PKCS8_bio := LoadLibCryptoFunction('i2d_PKCS8_bio');
  FuncLoadError := not assigned(i2d_PKCS8_bio);
  if FuncLoadError then
  begin
    i2d_PKCS8_bio :=  @ERROR_i2d_PKCS8_bio;
  end;

  d2i_PKCS8_PRIV_KEY_INFO_bio := LoadLibCryptoFunction('d2i_PKCS8_PRIV_KEY_INFO_bio');
  FuncLoadError := not assigned(d2i_PKCS8_PRIV_KEY_INFO_bio);
  if FuncLoadError then
  begin
    d2i_PKCS8_PRIV_KEY_INFO_bio :=  @ERROR_d2i_PKCS8_PRIV_KEY_INFO_bio;
  end;

  i2d_PKCS8_PRIV_KEY_INFO_bio := LoadLibCryptoFunction('i2d_PKCS8_PRIV_KEY_INFO_bio');
  FuncLoadError := not assigned(i2d_PKCS8_PRIV_KEY_INFO_bio);
  if FuncLoadError then
  begin
    i2d_PKCS8_PRIV_KEY_INFO_bio :=  @ERROR_i2d_PKCS8_PRIV_KEY_INFO_bio;
  end;

  i2d_PKCS8PrivateKeyInfo_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKeyInfo_bio');
  FuncLoadError := not assigned(i2d_PKCS8PrivateKeyInfo_bio);
  if FuncLoadError then
  begin
    i2d_PKCS8PrivateKeyInfo_bio :=  @ERROR_i2d_PKCS8PrivateKeyInfo_bio;
  end;

  i2d_PrivateKey_bio := LoadLibCryptoFunction('i2d_PrivateKey_bio');
  FuncLoadError := not assigned(i2d_PrivateKey_bio);
  if FuncLoadError then
  begin
    i2d_PrivateKey_bio :=  @ERROR_i2d_PrivateKey_bio;
  end;

  d2i_PrivateKey_bio := LoadLibCryptoFunction('d2i_PrivateKey_bio');
  FuncLoadError := not assigned(d2i_PrivateKey_bio);
  if FuncLoadError then
  begin
    d2i_PrivateKey_bio :=  @ERROR_d2i_PrivateKey_bio;
  end;

  i2d_PUBKEY_bio := LoadLibCryptoFunction('i2d_PUBKEY_bio');
  FuncLoadError := not assigned(i2d_PUBKEY_bio);
  if FuncLoadError then
  begin
    i2d_PUBKEY_bio :=  @ERROR_i2d_PUBKEY_bio;
  end;

  d2i_PUBKEY_bio := LoadLibCryptoFunction('d2i_PUBKEY_bio');
  FuncLoadError := not assigned(d2i_PUBKEY_bio);
  if FuncLoadError then
  begin
    d2i_PUBKEY_bio :=  @ERROR_d2i_PUBKEY_bio;
  end;

  X509_dup := LoadLibCryptoFunction('X509_dup');
  FuncLoadError := not assigned(X509_dup);
  if FuncLoadError then
  begin
    X509_dup :=  @ERROR_X509_dup;
  end;

  X509_ATTRIBUTE_dup := LoadLibCryptoFunction('X509_ATTRIBUTE_dup');
  FuncLoadError := not assigned(X509_ATTRIBUTE_dup);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_dup :=  @ERROR_X509_ATTRIBUTE_dup;
  end;

  X509_EXTENSION_dup := LoadLibCryptoFunction('X509_EXTENSION_dup');
  FuncLoadError := not assigned(X509_EXTENSION_dup);
  if FuncLoadError then
  begin
    X509_EXTENSION_dup :=  @ERROR_X509_EXTENSION_dup;
  end;

  X509_CRL_dup := LoadLibCryptoFunction('X509_CRL_dup');
  FuncLoadError := not assigned(X509_CRL_dup);
  if FuncLoadError then
  begin
    X509_CRL_dup :=  @ERROR_X509_CRL_dup;
  end;

  X509_REVOKED_dup := LoadLibCryptoFunction('X509_REVOKED_dup');
  FuncLoadError := not assigned(X509_REVOKED_dup);
  if FuncLoadError then
  begin
    X509_REVOKED_dup :=  @ERROR_X509_REVOKED_dup;
  end;

  X509_REQ_dup := LoadLibCryptoFunction('X509_REQ_dup');
  FuncLoadError := not assigned(X509_REQ_dup);
  if FuncLoadError then
  begin
    X509_REQ_dup :=  @ERROR_X509_REQ_dup;
  end;

  X509_ALGOR_dup := LoadLibCryptoFunction('X509_ALGOR_dup');
  FuncLoadError := not assigned(X509_ALGOR_dup);
  if FuncLoadError then
  begin
    X509_ALGOR_dup :=  @ERROR_X509_ALGOR_dup;
  end;

  X509_ALGOR_set0 := LoadLibCryptoFunction('X509_ALGOR_set0');
  FuncLoadError := not assigned(X509_ALGOR_set0);
  if FuncLoadError then
  begin
    X509_ALGOR_set0 :=  @ERROR_X509_ALGOR_set0;
  end;

  X509_ALGOR_get0 := LoadLibCryptoFunction('X509_ALGOR_get0');
  FuncLoadError := not assigned(X509_ALGOR_get0);
  if FuncLoadError then
  begin
    X509_ALGOR_get0 :=  @ERROR_X509_ALGOR_get0;
  end;

  X509_ALGOR_set_md := LoadLibCryptoFunction('X509_ALGOR_set_md');
  FuncLoadError := not assigned(X509_ALGOR_set_md);
  if FuncLoadError then
  begin
    X509_ALGOR_set_md :=  @ERROR_X509_ALGOR_set_md;
  end;

  X509_ALGOR_cmp := LoadLibCryptoFunction('X509_ALGOR_cmp');
  FuncLoadError := not assigned(X509_ALGOR_cmp);
  if FuncLoadError then
  begin
    X509_ALGOR_cmp :=  @ERROR_X509_ALGOR_cmp;
  end;

  X509_NAME_dup := LoadLibCryptoFunction('X509_NAME_dup');
  FuncLoadError := not assigned(X509_NAME_dup);
  if FuncLoadError then
  begin
    X509_NAME_dup :=  @ERROR_X509_NAME_dup;
  end;

  X509_NAME_ENTRY_dup := LoadLibCryptoFunction('X509_NAME_ENTRY_dup');
  FuncLoadError := not assigned(X509_NAME_ENTRY_dup);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_dup :=  @ERROR_X509_NAME_ENTRY_dup;
  end;

  X509_cmp_time := LoadLibCryptoFunction('X509_cmp_time');
  FuncLoadError := not assigned(X509_cmp_time);
  if FuncLoadError then
  begin
    X509_cmp_time :=  @ERROR_X509_cmp_time;
  end;

  X509_cmp_current_time := LoadLibCryptoFunction('X509_cmp_current_time');
  FuncLoadError := not assigned(X509_cmp_current_time);
  if FuncLoadError then
  begin
    X509_cmp_current_time :=  @ERROR_X509_cmp_current_time;
  end;

  X509_time_adj := LoadLibCryptoFunction('X509_time_adj');
  FuncLoadError := not assigned(X509_time_adj);
  if FuncLoadError then
  begin
    X509_time_adj :=  @ERROR_X509_time_adj;
  end;

  X509_time_adj_ex := LoadLibCryptoFunction('X509_time_adj_ex');
  FuncLoadError := not assigned(X509_time_adj_ex);
  if FuncLoadError then
  begin
    X509_time_adj_ex :=  @ERROR_X509_time_adj_ex;
  end;

  X509_gmtime_adj := LoadLibCryptoFunction('X509_gmtime_adj');
  FuncLoadError := not assigned(X509_gmtime_adj);
  if FuncLoadError then
  begin
    X509_gmtime_adj :=  @ERROR_X509_gmtime_adj;
  end;

  X509_get_default_cert_area := LoadLibCryptoFunction('X509_get_default_cert_area');
  FuncLoadError := not assigned(X509_get_default_cert_area);
  if FuncLoadError then
  begin
    X509_get_default_cert_area :=  @ERROR_X509_get_default_cert_area;
  end;

  X509_get_default_cert_dir := LoadLibCryptoFunction('X509_get_default_cert_dir');
  FuncLoadError := not assigned(X509_get_default_cert_dir);
  if FuncLoadError then
  begin
    X509_get_default_cert_dir :=  @ERROR_X509_get_default_cert_dir;
  end;

  X509_get_default_cert_file := LoadLibCryptoFunction('X509_get_default_cert_file');
  FuncLoadError := not assigned(X509_get_default_cert_file);
  if FuncLoadError then
  begin
    X509_get_default_cert_file :=  @ERROR_X509_get_default_cert_file;
  end;

  X509_get_default_cert_dir_env := LoadLibCryptoFunction('X509_get_default_cert_dir_env');
  FuncLoadError := not assigned(X509_get_default_cert_dir_env);
  if FuncLoadError then
  begin
    X509_get_default_cert_dir_env :=  @ERROR_X509_get_default_cert_dir_env;
  end;

  X509_get_default_cert_file_env := LoadLibCryptoFunction('X509_get_default_cert_file_env');
  FuncLoadError := not assigned(X509_get_default_cert_file_env);
  if FuncLoadError then
  begin
    X509_get_default_cert_file_env :=  @ERROR_X509_get_default_cert_file_env;
  end;

  X509_get_default_private_dir := LoadLibCryptoFunction('X509_get_default_private_dir');
  FuncLoadError := not assigned(X509_get_default_private_dir);
  if FuncLoadError then
  begin
    X509_get_default_private_dir :=  @ERROR_X509_get_default_private_dir;
  end;

  X509_to_X509_REQ := LoadLibCryptoFunction('X509_to_X509_REQ');
  FuncLoadError := not assigned(X509_to_X509_REQ);
  if FuncLoadError then
  begin
    X509_to_X509_REQ :=  @ERROR_X509_to_X509_REQ;
  end;

  X509_REQ_to_X509 := LoadLibCryptoFunction('X509_REQ_to_X509');
  FuncLoadError := not assigned(X509_REQ_to_X509);
  if FuncLoadError then
  begin
    X509_REQ_to_X509 :=  @ERROR_X509_REQ_to_X509;
  end;

  X509_ALGOR_new := LoadLibCryptoFunction('X509_ALGOR_new');
  FuncLoadError := not assigned(X509_ALGOR_new);
  if FuncLoadError then
  begin
    X509_ALGOR_new :=  @ERROR_X509_ALGOR_new;
  end;

  X509_ALGOR_free := LoadLibCryptoFunction('X509_ALGOR_free');
  FuncLoadError := not assigned(X509_ALGOR_free);
  if FuncLoadError then
  begin
    X509_ALGOR_free :=  @ERROR_X509_ALGOR_free;
  end;

  d2i_X509_ALGOR := LoadLibCryptoFunction('d2i_X509_ALGOR');
  FuncLoadError := not assigned(d2i_X509_ALGOR);
  if FuncLoadError then
  begin
    d2i_X509_ALGOR :=  @ERROR_d2i_X509_ALGOR;
  end;

  i2d_X509_ALGOR := LoadLibCryptoFunction('i2d_X509_ALGOR');
  FuncLoadError := not assigned(i2d_X509_ALGOR);
  if FuncLoadError then
  begin
    i2d_X509_ALGOR :=  @ERROR_i2d_X509_ALGOR;
  end;

  X509_VAL_new := LoadLibCryptoFunction('X509_VAL_new');
  FuncLoadError := not assigned(X509_VAL_new);
  if FuncLoadError then
  begin
    X509_VAL_new :=  @ERROR_X509_VAL_new;
  end;

  X509_VAL_free := LoadLibCryptoFunction('X509_VAL_free');
  FuncLoadError := not assigned(X509_VAL_free);
  if FuncLoadError then
  begin
    X509_VAL_free :=  @ERROR_X509_VAL_free;
  end;

  d2i_X509_VAL := LoadLibCryptoFunction('d2i_X509_VAL');
  FuncLoadError := not assigned(d2i_X509_VAL);
  if FuncLoadError then
  begin
    d2i_X509_VAL :=  @ERROR_d2i_X509_VAL;
  end;

  i2d_X509_VAL := LoadLibCryptoFunction('i2d_X509_VAL');
  FuncLoadError := not assigned(i2d_X509_VAL);
  if FuncLoadError then
  begin
    i2d_X509_VAL :=  @ERROR_i2d_X509_VAL;
  end;

  X509_PUBKEY_new := LoadLibCryptoFunction('X509_PUBKEY_new');
  FuncLoadError := not assigned(X509_PUBKEY_new);
  if FuncLoadError then
  begin
    X509_PUBKEY_new :=  @ERROR_X509_PUBKEY_new;
  end;

  X509_PUBKEY_free := LoadLibCryptoFunction('X509_PUBKEY_free');
  FuncLoadError := not assigned(X509_PUBKEY_free);
  if FuncLoadError then
  begin
    X509_PUBKEY_free :=  @ERROR_X509_PUBKEY_free;
  end;

  d2i_X509_PUBKEY := LoadLibCryptoFunction('d2i_X509_PUBKEY');
  FuncLoadError := not assigned(d2i_X509_PUBKEY);
  if FuncLoadError then
  begin
    d2i_X509_PUBKEY :=  @ERROR_d2i_X509_PUBKEY;
  end;

  i2d_X509_PUBKEY := LoadLibCryptoFunction('i2d_X509_PUBKEY');
  FuncLoadError := not assigned(i2d_X509_PUBKEY);
  if FuncLoadError then
  begin
    i2d_X509_PUBKEY :=  @ERROR_i2d_X509_PUBKEY;
  end;

  X509_PUBKEY_set := LoadLibCryptoFunction('X509_PUBKEY_set');
  FuncLoadError := not assigned(X509_PUBKEY_set);
  if FuncLoadError then
  begin
    X509_PUBKEY_set :=  @ERROR_X509_PUBKEY_set;
  end;

  X509_PUBKEY_get0 := LoadLibCryptoFunction('X509_PUBKEY_get0');
  FuncLoadError := not assigned(X509_PUBKEY_get0);
  if FuncLoadError then
  begin
    X509_PUBKEY_get0 :=  @ERROR_X509_PUBKEY_get0;
  end;

  X509_PUBKEY_get := LoadLibCryptoFunction('X509_PUBKEY_get');
  FuncLoadError := not assigned(X509_PUBKEY_get);
  if FuncLoadError then
  begin
    X509_PUBKEY_get :=  @ERROR_X509_PUBKEY_get;
  end;

  X509_get_pathlen := LoadLibCryptoFunction('X509_get_pathlen');
  FuncLoadError := not assigned(X509_get_pathlen);
  if FuncLoadError then
  begin
    X509_get_pathlen :=  @ERROR_X509_get_pathlen;
  end;

  i2d_PUBKEY := LoadLibCryptoFunction('i2d_PUBKEY');
  FuncLoadError := not assigned(i2d_PUBKEY);
  if FuncLoadError then
  begin
    i2d_PUBKEY :=  @ERROR_i2d_PUBKEY;
  end;

  d2i_PUBKEY := LoadLibCryptoFunction('d2i_PUBKEY');
  FuncLoadError := not assigned(d2i_PUBKEY);
  if FuncLoadError then
  begin
    d2i_PUBKEY :=  @ERROR_d2i_PUBKEY;
  end;

  i2d_RSA_PUBKEY := LoadLibCryptoFunction('i2d_RSA_PUBKEY');
  FuncLoadError := not assigned(i2d_RSA_PUBKEY);
  if FuncLoadError then
  begin
    i2d_RSA_PUBKEY :=  @ERROR_i2d_RSA_PUBKEY;
  end;

  d2i_RSA_PUBKEY := LoadLibCryptoFunction('d2i_RSA_PUBKEY');
  FuncLoadError := not assigned(d2i_RSA_PUBKEY);
  if FuncLoadError then
  begin
    d2i_RSA_PUBKEY :=  @ERROR_d2i_RSA_PUBKEY;
  end;

  i2d_DSA_PUBKEY := LoadLibCryptoFunction('i2d_DSA_PUBKEY');
  FuncLoadError := not assigned(i2d_DSA_PUBKEY);
  if FuncLoadError then
  begin
    i2d_DSA_PUBKEY :=  @ERROR_i2d_DSA_PUBKEY;
  end;

  d2i_DSA_PUBKEY := LoadLibCryptoFunction('d2i_DSA_PUBKEY');
  FuncLoadError := not assigned(d2i_DSA_PUBKEY);
  if FuncLoadError then
  begin
    d2i_DSA_PUBKEY :=  @ERROR_d2i_DSA_PUBKEY;
  end;

  i2d_EC_PUBKEY := LoadLibCryptoFunction('i2d_EC_PUBKEY');
  FuncLoadError := not assigned(i2d_EC_PUBKEY);
  if FuncLoadError then
  begin
    i2d_EC_PUBKEY :=  @ERROR_i2d_EC_PUBKEY;
  end;

  d2i_EC_PUBKEY := LoadLibCryptoFunction('d2i_EC_PUBKEY');
  FuncLoadError := not assigned(d2i_EC_PUBKEY);
  if FuncLoadError then
  begin
    d2i_EC_PUBKEY :=  @ERROR_d2i_EC_PUBKEY;
  end;

  X509_SIG_new := LoadLibCryptoFunction('X509_SIG_new');
  FuncLoadError := not assigned(X509_SIG_new);
  if FuncLoadError then
  begin
    X509_SIG_new :=  @ERROR_X509_SIG_new;
  end;

  X509_SIG_free := LoadLibCryptoFunction('X509_SIG_free');
  FuncLoadError := not assigned(X509_SIG_free);
  if FuncLoadError then
  begin
    X509_SIG_free :=  @ERROR_X509_SIG_free;
  end;

  d2i_X509_SIG := LoadLibCryptoFunction('d2i_X509_SIG');
  FuncLoadError := not assigned(d2i_X509_SIG);
  if FuncLoadError then
  begin
    d2i_X509_SIG :=  @ERROR_d2i_X509_SIG;
  end;

  i2d_X509_SIG := LoadLibCryptoFunction('i2d_X509_SIG');
  FuncLoadError := not assigned(i2d_X509_SIG);
  if FuncLoadError then
  begin
    i2d_X509_SIG :=  @ERROR_i2d_X509_SIG;
  end;

  X509_SIG_get0 := LoadLibCryptoFunction('X509_SIG_get0');
  FuncLoadError := not assigned(X509_SIG_get0);
  if FuncLoadError then
  begin
    X509_SIG_get0 :=  @ERROR_X509_SIG_get0;
  end;

  X509_SIG_getm := LoadLibCryptoFunction('X509_SIG_getm');
  FuncLoadError := not assigned(X509_SIG_getm);
  if FuncLoadError then
  begin
    X509_SIG_getm :=  @ERROR_X509_SIG_getm;
  end;

  X509_REQ_INFO_new := LoadLibCryptoFunction('X509_REQ_INFO_new');
  FuncLoadError := not assigned(X509_REQ_INFO_new);
  if FuncLoadError then
  begin
    X509_REQ_INFO_new :=  @ERROR_X509_REQ_INFO_new;
  end;

  X509_REQ_INFO_free := LoadLibCryptoFunction('X509_REQ_INFO_free');
  FuncLoadError := not assigned(X509_REQ_INFO_free);
  if FuncLoadError then
  begin
    X509_REQ_INFO_free :=  @ERROR_X509_REQ_INFO_free;
  end;

  d2i_X509_REQ_INFO := LoadLibCryptoFunction('d2i_X509_REQ_INFO');
  FuncLoadError := not assigned(d2i_X509_REQ_INFO);
  if FuncLoadError then
  begin
    d2i_X509_REQ_INFO :=  @ERROR_d2i_X509_REQ_INFO;
  end;

  i2d_X509_REQ_INFO := LoadLibCryptoFunction('i2d_X509_REQ_INFO');
  FuncLoadError := not assigned(i2d_X509_REQ_INFO);
  if FuncLoadError then
  begin
    i2d_X509_REQ_INFO :=  @ERROR_i2d_X509_REQ_INFO;
  end;

  X509_REQ_new := LoadLibCryptoFunction('X509_REQ_new');
  FuncLoadError := not assigned(X509_REQ_new);
  if FuncLoadError then
  begin
    X509_REQ_new :=  @ERROR_X509_REQ_new;
  end;

  X509_REQ_free := LoadLibCryptoFunction('X509_REQ_free');
  FuncLoadError := not assigned(X509_REQ_free);
  if FuncLoadError then
  begin
    X509_REQ_free :=  @ERROR_X509_REQ_free;
  end;

  d2i_X509_REQ := LoadLibCryptoFunction('d2i_X509_REQ');
  FuncLoadError := not assigned(d2i_X509_REQ);
  if FuncLoadError then
  begin
    d2i_X509_REQ :=  @ERROR_d2i_X509_REQ;
  end;

  i2d_X509_REQ := LoadLibCryptoFunction('i2d_X509_REQ');
  FuncLoadError := not assigned(i2d_X509_REQ);
  if FuncLoadError then
  begin
    i2d_X509_REQ :=  @ERROR_i2d_X509_REQ;
  end;

  X509_ATTRIBUTE_new := LoadLibCryptoFunction('X509_ATTRIBUTE_new');
  FuncLoadError := not assigned(X509_ATTRIBUTE_new);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_new :=  @ERROR_X509_ATTRIBUTE_new;
  end;

  X509_ATTRIBUTE_free := LoadLibCryptoFunction('X509_ATTRIBUTE_free');
  FuncLoadError := not assigned(X509_ATTRIBUTE_free);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_free :=  @ERROR_X509_ATTRIBUTE_free;
  end;

  d2i_X509_ATTRIBUTE := LoadLibCryptoFunction('d2i_X509_ATTRIBUTE');
  FuncLoadError := not assigned(d2i_X509_ATTRIBUTE);
  if FuncLoadError then
  begin
    d2i_X509_ATTRIBUTE :=  @ERROR_d2i_X509_ATTRIBUTE;
  end;

  i2d_X509_ATTRIBUTE := LoadLibCryptoFunction('i2d_X509_ATTRIBUTE');
  FuncLoadError := not assigned(i2d_X509_ATTRIBUTE);
  if FuncLoadError then
  begin
    i2d_X509_ATTRIBUTE :=  @ERROR_i2d_X509_ATTRIBUTE;
  end;

  X509_ATTRIBUTE_create := LoadLibCryptoFunction('X509_ATTRIBUTE_create');
  FuncLoadError := not assigned(X509_ATTRIBUTE_create);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_create :=  @ERROR_X509_ATTRIBUTE_create;
  end;

  X509_EXTENSION_new := LoadLibCryptoFunction('X509_EXTENSION_new');
  FuncLoadError := not assigned(X509_EXTENSION_new);
  if FuncLoadError then
  begin
    X509_EXTENSION_new :=  @ERROR_X509_EXTENSION_new;
  end;

  X509_EXTENSION_free := LoadLibCryptoFunction('X509_EXTENSION_free');
  FuncLoadError := not assigned(X509_EXTENSION_free);
  if FuncLoadError then
  begin
    X509_EXTENSION_free :=  @ERROR_X509_EXTENSION_free;
  end;

  d2i_X509_EXTENSION := LoadLibCryptoFunction('d2i_X509_EXTENSION');
  FuncLoadError := not assigned(d2i_X509_EXTENSION);
  if FuncLoadError then
  begin
    d2i_X509_EXTENSION :=  @ERROR_d2i_X509_EXTENSION;
  end;

  i2d_X509_EXTENSION := LoadLibCryptoFunction('i2d_X509_EXTENSION');
  FuncLoadError := not assigned(i2d_X509_EXTENSION);
  if FuncLoadError then
  begin
    i2d_X509_EXTENSION :=  @ERROR_i2d_X509_EXTENSION;
  end;

  X509_NAME_ENTRY_new := LoadLibCryptoFunction('X509_NAME_ENTRY_new');
  FuncLoadError := not assigned(X509_NAME_ENTRY_new);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_new :=  @ERROR_X509_NAME_ENTRY_new;
  end;

  X509_NAME_ENTRY_free := LoadLibCryptoFunction('X509_NAME_ENTRY_free');
  FuncLoadError := not assigned(X509_NAME_ENTRY_free);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_free :=  @ERROR_X509_NAME_ENTRY_free;
  end;

  d2i_X509_NAME_ENTRY := LoadLibCryptoFunction('d2i_X509_NAME_ENTRY');
  FuncLoadError := not assigned(d2i_X509_NAME_ENTRY);
  if FuncLoadError then
  begin
    d2i_X509_NAME_ENTRY :=  @ERROR_d2i_X509_NAME_ENTRY;
  end;

  i2d_X509_NAME_ENTRY := LoadLibCryptoFunction('i2d_X509_NAME_ENTRY');
  FuncLoadError := not assigned(i2d_X509_NAME_ENTRY);
  if FuncLoadError then
  begin
    i2d_X509_NAME_ENTRY :=  @ERROR_i2d_X509_NAME_ENTRY;
  end;

  X509_NAME_new := LoadLibCryptoFunction('X509_NAME_new');
  FuncLoadError := not assigned(X509_NAME_new);
  if FuncLoadError then
  begin
    X509_NAME_new :=  @ERROR_X509_NAME_new;
  end;

  X509_NAME_free := LoadLibCryptoFunction('X509_NAME_free');
  FuncLoadError := not assigned(X509_NAME_free);
  if FuncLoadError then
  begin
    X509_NAME_free :=  @ERROR_X509_NAME_free;
  end;

  d2i_X509_NAME := LoadLibCryptoFunction('d2i_X509_NAME');
  FuncLoadError := not assigned(d2i_X509_NAME);
  if FuncLoadError then
  begin
    d2i_X509_NAME :=  @ERROR_d2i_X509_NAME;
  end;

  i2d_X509_NAME := LoadLibCryptoFunction('i2d_X509_NAME');
  FuncLoadError := not assigned(i2d_X509_NAME);
  if FuncLoadError then
  begin
    i2d_X509_NAME :=  @ERROR_i2d_X509_NAME;
  end;

  X509_NAME_set := LoadLibCryptoFunction('X509_NAME_set');
  FuncLoadError := not assigned(X509_NAME_set);
  if FuncLoadError then
  begin
    X509_NAME_set :=  @ERROR_X509_NAME_set;
  end;

  X509_new := LoadLibCryptoFunction('X509_new');
  FuncLoadError := not assigned(X509_new);
  if FuncLoadError then
  begin
    X509_new :=  @ERROR_X509_new;
  end;

  X509_free := LoadLibCryptoFunction('X509_free');
  FuncLoadError := not assigned(X509_free);
  if FuncLoadError then
  begin
    X509_free :=  @ERROR_X509_free;
  end;

  d2i_X509 := LoadLibCryptoFunction('d2i_X509');
  FuncLoadError := not assigned(d2i_X509);
  if FuncLoadError then
  begin
    d2i_X509 :=  @ERROR_d2i_X509;
  end;

  i2d_X509 := LoadLibCryptoFunction('i2d_X509');
  FuncLoadError := not assigned(i2d_X509);
  if FuncLoadError then
  begin
    i2d_X509 :=  @ERROR_i2d_X509;
  end;

  X509_set_ex_data := LoadLibCryptoFunction('X509_set_ex_data');
  FuncLoadError := not assigned(X509_set_ex_data);
  if FuncLoadError then
  begin
    X509_set_ex_data :=  @ERROR_X509_set_ex_data;
  end;

  X509_get_ex_data := LoadLibCryptoFunction('X509_get_ex_data');
  FuncLoadError := not assigned(X509_get_ex_data);
  if FuncLoadError then
  begin
    X509_get_ex_data :=  @ERROR_X509_get_ex_data;
  end;

  i2d_X509_AUX := LoadLibCryptoFunction('i2d_X509_AUX');
  FuncLoadError := not assigned(i2d_X509_AUX);
  if FuncLoadError then
  begin
    i2d_X509_AUX :=  @ERROR_i2d_X509_AUX;
  end;

  d2i_X509_AUX := LoadLibCryptoFunction('d2i_X509_AUX');
  FuncLoadError := not assigned(d2i_X509_AUX);
  if FuncLoadError then
  begin
    d2i_X509_AUX :=  @ERROR_d2i_X509_AUX;
  end;

  i2d_re_X509_tbs := LoadLibCryptoFunction('i2d_re_X509_tbs');
  FuncLoadError := not assigned(i2d_re_X509_tbs);
  if FuncLoadError then
  begin
    i2d_re_X509_tbs :=  @ERROR_i2d_re_X509_tbs;
  end;

  X509_SIG_INFO_get := LoadLibCryptoFunction('X509_SIG_INFO_get');
  FuncLoadError := not assigned(X509_SIG_INFO_get);
  if FuncLoadError then
  begin
    X509_SIG_INFO_get :=  @ERROR_X509_SIG_INFO_get;
  end;

  X509_SIG_INFO_set := LoadLibCryptoFunction('X509_SIG_INFO_set');
  FuncLoadError := not assigned(X509_SIG_INFO_set);
  if FuncLoadError then
  begin
    X509_SIG_INFO_set :=  @ERROR_X509_SIG_INFO_set;
  end;

  X509_get_signature_info := LoadLibCryptoFunction('X509_get_signature_info');
  FuncLoadError := not assigned(X509_get_signature_info);
  if FuncLoadError then
  begin
    X509_get_signature_info :=  @ERROR_X509_get_signature_info;
  end;

  X509_get0_signature := LoadLibCryptoFunction('X509_get0_signature');
  FuncLoadError := not assigned(X509_get0_signature);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get0_signature := @COMPAT_X509_get0_signature;
{$ELSE}
    X509_get0_signature :=  @ERROR_X509_get0_signature;
{$ENDIF}
  end;

  X509_get_signature_nid := LoadLibCryptoFunction('X509_get_signature_nid');
  FuncLoadError := not assigned(X509_get_signature_nid);
  if FuncLoadError then
  begin
    X509_get_signature_nid :=  @ERROR_X509_get_signature_nid;
  end;

  X509_trusted := LoadLibCryptoFunction('X509_trusted');
  FuncLoadError := not assigned(X509_trusted);
  if FuncLoadError then
  begin
    X509_trusted :=  @ERROR_X509_trusted;
  end;

  X509_alias_set1 := LoadLibCryptoFunction('X509_alias_set1');
  FuncLoadError := not assigned(X509_alias_set1);
  if FuncLoadError then
  begin
    X509_alias_set1 :=  @ERROR_X509_alias_set1;
  end;

  X509_keyid_set1 := LoadLibCryptoFunction('X509_keyid_set1');
  FuncLoadError := not assigned(X509_keyid_set1);
  if FuncLoadError then
  begin
    X509_keyid_set1 :=  @ERROR_X509_keyid_set1;
  end;

  X509_alias_get0 := LoadLibCryptoFunction('X509_alias_get0');
  FuncLoadError := not assigned(X509_alias_get0);
  if FuncLoadError then
  begin
    X509_alias_get0 :=  @ERROR_X509_alias_get0;
  end;

  X509_keyid_get0 := LoadLibCryptoFunction('X509_keyid_get0');
  FuncLoadError := not assigned(X509_keyid_get0);
  if FuncLoadError then
  begin
    X509_keyid_get0 :=  @ERROR_X509_keyid_get0;
  end;

  X509_TRUST_set := LoadLibCryptoFunction('X509_TRUST_set');
  FuncLoadError := not assigned(X509_TRUST_set);
  if FuncLoadError then
  begin
    X509_TRUST_set :=  @ERROR_X509_TRUST_set;
  end;

  X509_add1_trust_object := LoadLibCryptoFunction('X509_add1_trust_object');
  FuncLoadError := not assigned(X509_add1_trust_object);
  if FuncLoadError then
  begin
    X509_add1_trust_object :=  @ERROR_X509_add1_trust_object;
  end;

  X509_add1_reject_object := LoadLibCryptoFunction('X509_add1_reject_object');
  FuncLoadError := not assigned(X509_add1_reject_object);
  if FuncLoadError then
  begin
    X509_add1_reject_object :=  @ERROR_X509_add1_reject_object;
  end;

  X509_trust_clear := LoadLibCryptoFunction('X509_trust_clear');
  FuncLoadError := not assigned(X509_trust_clear);
  if FuncLoadError then
  begin
    X509_trust_clear :=  @ERROR_X509_trust_clear;
  end;

  X509_reject_clear := LoadLibCryptoFunction('X509_reject_clear');
  FuncLoadError := not assigned(X509_reject_clear);
  if FuncLoadError then
  begin
    X509_reject_clear :=  @ERROR_X509_reject_clear;
  end;

  X509_REVOKED_new := LoadLibCryptoFunction('X509_REVOKED_new');
  FuncLoadError := not assigned(X509_REVOKED_new);
  if FuncLoadError then
  begin
    X509_REVOKED_new :=  @ERROR_X509_REVOKED_new;
  end;

  X509_REVOKED_free := LoadLibCryptoFunction('X509_REVOKED_free');
  FuncLoadError := not assigned(X509_REVOKED_free);
  if FuncLoadError then
  begin
    X509_REVOKED_free :=  @ERROR_X509_REVOKED_free;
  end;

  d2i_X509_REVOKED := LoadLibCryptoFunction('d2i_X509_REVOKED');
  FuncLoadError := not assigned(d2i_X509_REVOKED);
  if FuncLoadError then
  begin
    d2i_X509_REVOKED :=  @ERROR_d2i_X509_REVOKED;
  end;

  i2d_X509_REVOKED := LoadLibCryptoFunction('i2d_X509_REVOKED');
  FuncLoadError := not assigned(i2d_X509_REVOKED);
  if FuncLoadError then
  begin
    i2d_X509_REVOKED :=  @ERROR_i2d_X509_REVOKED;
  end;

  X509_CRL_INFO_new := LoadLibCryptoFunction('X509_CRL_INFO_new');
  FuncLoadError := not assigned(X509_CRL_INFO_new);
  if FuncLoadError then
  begin
    X509_CRL_INFO_new :=  @ERROR_X509_CRL_INFO_new;
  end;

  X509_CRL_INFO_free := LoadLibCryptoFunction('X509_CRL_INFO_free');
  FuncLoadError := not assigned(X509_CRL_INFO_free);
  if FuncLoadError then
  begin
    X509_CRL_INFO_free :=  @ERROR_X509_CRL_INFO_free;
  end;

  d2i_X509_CRL_INFO := LoadLibCryptoFunction('d2i_X509_CRL_INFO');
  FuncLoadError := not assigned(d2i_X509_CRL_INFO);
  if FuncLoadError then
  begin
    d2i_X509_CRL_INFO :=  @ERROR_d2i_X509_CRL_INFO;
  end;

  i2d_X509_CRL_INFO := LoadLibCryptoFunction('i2d_X509_CRL_INFO');
  FuncLoadError := not assigned(i2d_X509_CRL_INFO);
  if FuncLoadError then
  begin
    i2d_X509_CRL_INFO :=  @ERROR_i2d_X509_CRL_INFO;
  end;

  X509_CRL_new := LoadLibCryptoFunction('X509_CRL_new');
  FuncLoadError := not assigned(X509_CRL_new);
  if FuncLoadError then
  begin
    X509_CRL_new :=  @ERROR_X509_CRL_new;
  end;

  X509_CRL_free := LoadLibCryptoFunction('X509_CRL_free');
  FuncLoadError := not assigned(X509_CRL_free);
  if FuncLoadError then
  begin
    X509_CRL_free :=  @ERROR_X509_CRL_free;
  end;

  d2i_X509_CRL := LoadLibCryptoFunction('d2i_X509_CRL');
  FuncLoadError := not assigned(d2i_X509_CRL);
  if FuncLoadError then
  begin
    d2i_X509_CRL :=  @ERROR_d2i_X509_CRL;
  end;

  i2d_X509_CRL := LoadLibCryptoFunction('i2d_X509_CRL');
  FuncLoadError := not assigned(i2d_X509_CRL);
  if FuncLoadError then
  begin
    i2d_X509_CRL :=  @ERROR_i2d_X509_CRL;
  end;

  X509_CRL_add0_revoked := LoadLibCryptoFunction('X509_CRL_add0_revoked');
  FuncLoadError := not assigned(X509_CRL_add0_revoked);
  if FuncLoadError then
  begin
    X509_CRL_add0_revoked :=  @ERROR_X509_CRL_add0_revoked;
  end;

  X509_CRL_get0_by_serial := LoadLibCryptoFunction('X509_CRL_get0_by_serial');
  FuncLoadError := not assigned(X509_CRL_get0_by_serial);
  if FuncLoadError then
  begin
    X509_CRL_get0_by_serial :=  @ERROR_X509_CRL_get0_by_serial;
  end;

  X509_CRL_get0_by_cert := LoadLibCryptoFunction('X509_CRL_get0_by_cert');
  FuncLoadError := not assigned(X509_CRL_get0_by_cert);
  if FuncLoadError then
  begin
    X509_CRL_get0_by_cert :=  @ERROR_X509_CRL_get0_by_cert;
  end;

  X509_PKEY_new := LoadLibCryptoFunction('X509_PKEY_new');
  FuncLoadError := not assigned(X509_PKEY_new);
  if FuncLoadError then
  begin
    X509_PKEY_new :=  @ERROR_X509_PKEY_new;
  end;

  X509_PKEY_free := LoadLibCryptoFunction('X509_PKEY_free');
  FuncLoadError := not assigned(X509_PKEY_free);
  if FuncLoadError then
  begin
    X509_PKEY_free :=  @ERROR_X509_PKEY_free;
  end;

  X509_INFO_new := LoadLibCryptoFunction('X509_INFO_new');
  FuncLoadError := not assigned(X509_INFO_new);
  if FuncLoadError then
  begin
    X509_INFO_new :=  @ERROR_X509_INFO_new;
  end;

  X509_INFO_free := LoadLibCryptoFunction('X509_INFO_free');
  FuncLoadError := not assigned(X509_INFO_free);
  if FuncLoadError then
  begin
    X509_INFO_free :=  @ERROR_X509_INFO_free;
  end;

  X509_NAME_oneline := LoadLibCryptoFunction('X509_NAME_oneline');
  FuncLoadError := not assigned(X509_NAME_oneline);
  if FuncLoadError then
  begin
    X509_NAME_oneline :=  @ERROR_X509_NAME_oneline;
  end;

  ASN1_item_digest := LoadLibCryptoFunction('ASN1_item_digest');
  FuncLoadError := not assigned(ASN1_item_digest);
  if FuncLoadError then
  begin
    ASN1_item_digest :=  @ERROR_ASN1_item_digest;
  end;

  ASN1_item_verify := LoadLibCryptoFunction('ASN1_item_verify');
  FuncLoadError := not assigned(ASN1_item_verify);
  if FuncLoadError then
  begin
    ASN1_item_verify :=  @ERROR_ASN1_item_verify;
  end;

  ASN1_item_sign := LoadLibCryptoFunction('ASN1_item_sign');
  FuncLoadError := not assigned(ASN1_item_sign);
  if FuncLoadError then
  begin
    ASN1_item_sign :=  @ERROR_ASN1_item_sign;
  end;

  ASN1_item_sign_ctx := LoadLibCryptoFunction('ASN1_item_sign_ctx');
  FuncLoadError := not assigned(ASN1_item_sign_ctx);
  if FuncLoadError then
  begin
    ASN1_item_sign_ctx :=  @ERROR_ASN1_item_sign_ctx;
  end;

  X509_get_version := LoadLibCryptoFunction('X509_get_version');
  FuncLoadError := not assigned(X509_get_version);
  if FuncLoadError then
  begin
    X509_get_version :=  @ERROR_X509_get_version;
  end;

  X509_set_version := LoadLibCryptoFunction('X509_set_version');
  FuncLoadError := not assigned(X509_set_version);
  if FuncLoadError then
  begin
    X509_set_version :=  @ERROR_X509_set_version;
  end;

  X509_set_serialNumber := LoadLibCryptoFunction('X509_set_serialNumber');
  FuncLoadError := not assigned(X509_set_serialNumber);
  if FuncLoadError then
  begin
    X509_set_serialNumber :=  @ERROR_X509_set_serialNumber;
  end;

  X509_get_serialNumber := LoadLibCryptoFunction('X509_get_serialNumber');
  FuncLoadError := not assigned(X509_get_serialNumber);
  if FuncLoadError then
  begin
    X509_get_serialNumber :=  @ERROR_X509_get_serialNumber;
  end;

  X509_get0_serialNumber := LoadLibCryptoFunction('X509_get0_serialNumber');
  FuncLoadError := not assigned(X509_get0_serialNumber);
  if FuncLoadError then
  begin
    X509_get0_serialNumber :=  @ERROR_X509_get0_serialNumber;
  end;

  X509_set_issuer_name := LoadLibCryptoFunction('X509_set_issuer_name');
  FuncLoadError := not assigned(X509_set_issuer_name);
  if FuncLoadError then
  begin
    X509_set_issuer_name :=  @ERROR_X509_set_issuer_name;
  end;

  X509_get_issuer_name := LoadLibCryptoFunction('X509_get_issuer_name');
  FuncLoadError := not assigned(X509_get_issuer_name);
  if FuncLoadError then
  begin
    X509_get_issuer_name :=  @ERROR_X509_get_issuer_name;
  end;

  X509_set_subject_name := LoadLibCryptoFunction('X509_set_subject_name');
  FuncLoadError := not assigned(X509_set_subject_name);
  if FuncLoadError then
  begin
    X509_set_subject_name :=  @ERROR_X509_set_subject_name;
  end;

  X509_get_subject_name := LoadLibCryptoFunction('X509_get_subject_name');
  FuncLoadError := not assigned(X509_get_subject_name);
  if FuncLoadError then
  begin
    X509_get_subject_name :=  @ERROR_X509_get_subject_name;
  end;

  X509_get0_notBefore := LoadLibCryptoFunction('X509_get0_notBefore');
  FuncLoadError := not assigned(X509_get0_notBefore);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get0_notBefore := @COMPAT_X509_get0_notBefore;
{$ELSE}
    X509_get0_notBefore :=  @ERROR_X509_get0_notBefore;
{$ENDIF}
  end;

  X509_getm_notBefore := LoadLibCryptoFunction('X509_getm_notBefore');
  FuncLoadError := not assigned(X509_getm_notBefore);
  if FuncLoadError then
  begin
    X509_getm_notBefore :=  @ERROR_X509_getm_notBefore;
  end;

  X509_set1_notBefore := LoadLibCryptoFunction('X509_set1_notBefore');
  FuncLoadError := not assigned(X509_set1_notBefore);
  if FuncLoadError then
  begin
    X509_set1_notBefore :=  @ERROR_X509_set1_notBefore;
  end;

  X509_get0_notAfter := LoadLibCryptoFunction('X509_get0_notAfter');
  FuncLoadError := not assigned(X509_get0_notAfter);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get0_notAfter := @COMPAT_X509_get0_notAfter;
{$ELSE}
    X509_get0_notAfter :=  @ERROR_X509_get0_notAfter;
{$ENDIF}
  end;

  X509_getm_notAfter := LoadLibCryptoFunction('X509_getm_notAfter');
  FuncLoadError := not assigned(X509_getm_notAfter);
  if FuncLoadError then
  begin
    X509_getm_notAfter :=  @ERROR_X509_getm_notAfter;
  end;

  X509_set1_notAfter := LoadLibCryptoFunction('X509_set1_notAfter');
  FuncLoadError := not assigned(X509_set1_notAfter);
  if FuncLoadError then
  begin
    X509_set1_notAfter :=  @ERROR_X509_set1_notAfter;
  end;

  X509_set_pubkey := LoadLibCryptoFunction('X509_set_pubkey');
  FuncLoadError := not assigned(X509_set_pubkey);
  if FuncLoadError then
  begin
    X509_set_pubkey :=  @ERROR_X509_set_pubkey;
  end;

  X509_up_ref := LoadLibCryptoFunction('X509_up_ref');
  FuncLoadError := not assigned(X509_up_ref);
  if FuncLoadError then
  begin
    X509_up_ref :=  @ERROR_X509_up_ref;
  end;

  X509_get_signature_type := LoadLibCryptoFunction('X509_get_signature_type');
  FuncLoadError := not assigned(X509_get_signature_type);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get_signature_type := @COMPAT_X509_get_signature_type;
{$ELSE}
    X509_get_signature_type :=  @ERROR_X509_get_signature_type;
{$ENDIF}
  end;

  X509_get_X509_PUBKEY := LoadLibCryptoFunction('X509_get_X509_PUBKEY');
  FuncLoadError := not assigned(X509_get_X509_PUBKEY);
  if FuncLoadError then
  begin
    X509_get_X509_PUBKEY :=  @ERROR_X509_get_X509_PUBKEY;
  end;

  X509_get0_uids := LoadLibCryptoFunction('X509_get0_uids');
  FuncLoadError := not assigned(X509_get0_uids);
  if FuncLoadError then
  begin
    X509_get0_uids :=  @ERROR_X509_get0_uids;
  end;

  X509_get0_tbs_sigalg := LoadLibCryptoFunction('X509_get0_tbs_sigalg');
  FuncLoadError := not assigned(X509_get0_tbs_sigalg);
  if FuncLoadError then
  begin
    X509_get0_tbs_sigalg :=  @ERROR_X509_get0_tbs_sigalg;
  end;

  X509_get0_pubkey := LoadLibCryptoFunction('X509_get0_pubkey');
  FuncLoadError := not assigned(X509_get0_pubkey);
  if FuncLoadError then
  begin
    X509_get0_pubkey :=  @ERROR_X509_get0_pubkey;
  end;

  X509_get_pubkey := LoadLibCryptoFunction('X509_get_pubkey');
  FuncLoadError := not assigned(X509_get_pubkey);
  if FuncLoadError then
  begin
    X509_get_pubkey :=  @ERROR_X509_get_pubkey;
  end;

  X509_get0_pubkey_bitstr := LoadLibCryptoFunction('X509_get0_pubkey_bitstr');
  FuncLoadError := not assigned(X509_get0_pubkey_bitstr);
  if FuncLoadError then
  begin
    X509_get0_pubkey_bitstr :=  @ERROR_X509_get0_pubkey_bitstr;
  end;

  X509_certificate_type := LoadLibCryptoFunction('X509_certificate_type');
  FuncLoadError := not assigned(X509_certificate_type);
  if FuncLoadError then
  begin
    X509_certificate_type :=  @ERROR_X509_certificate_type;
  end;

  X509_REQ_get_version := LoadLibCryptoFunction('X509_REQ_get_version');
  FuncLoadError := not assigned(X509_REQ_get_version);
  if FuncLoadError then
  begin
    X509_REQ_get_version :=  @ERROR_X509_REQ_get_version;
  end;

  X509_REQ_set_version := LoadLibCryptoFunction('X509_REQ_set_version');
  FuncLoadError := not assigned(X509_REQ_set_version);
  if FuncLoadError then
  begin
    X509_REQ_set_version :=  @ERROR_X509_REQ_set_version;
  end;

  X509_REQ_get_subject_name := LoadLibCryptoFunction('X509_REQ_get_subject_name');
  FuncLoadError := not assigned(X509_REQ_get_subject_name);
  if FuncLoadError then
  begin
    X509_REQ_get_subject_name :=  @ERROR_X509_REQ_get_subject_name;
  end;

  X509_REQ_set_subject_name := LoadLibCryptoFunction('X509_REQ_set_subject_name');
  FuncLoadError := not assigned(X509_REQ_set_subject_name);
  if FuncLoadError then
  begin
    X509_REQ_set_subject_name :=  @ERROR_X509_REQ_set_subject_name;
  end;

  X509_REQ_get0_signature := LoadLibCryptoFunction('X509_REQ_get0_signature');
  FuncLoadError := not assigned(X509_REQ_get0_signature);
  if FuncLoadError then
  begin
    X509_REQ_get0_signature :=  @ERROR_X509_REQ_get0_signature;
  end;

  X509_REQ_get_signature_nid := LoadLibCryptoFunction('X509_REQ_get_signature_nid');
  FuncLoadError := not assigned(X509_REQ_get_signature_nid);
  if FuncLoadError then
  begin
    X509_REQ_get_signature_nid :=  @ERROR_X509_REQ_get_signature_nid;
  end;

  i2d_re_X509_REQ_tbs := LoadLibCryptoFunction('i2d_re_X509_REQ_tbs');
  FuncLoadError := not assigned(i2d_re_X509_REQ_tbs);
  if FuncLoadError then
  begin
    i2d_re_X509_REQ_tbs :=  @ERROR_i2d_re_X509_REQ_tbs;
  end;

  X509_REQ_set_pubkey := LoadLibCryptoFunction('X509_REQ_set_pubkey');
  FuncLoadError := not assigned(X509_REQ_set_pubkey);
  if FuncLoadError then
  begin
    X509_REQ_set_pubkey :=  @ERROR_X509_REQ_set_pubkey;
  end;

  X509_REQ_get_pubkey := LoadLibCryptoFunction('X509_REQ_get_pubkey');
  FuncLoadError := not assigned(X509_REQ_get_pubkey);
  if FuncLoadError then
  begin
    X509_REQ_get_pubkey :=  @ERROR_X509_REQ_get_pubkey;
  end;

  X509_REQ_get0_pubkey := LoadLibCryptoFunction('X509_REQ_get0_pubkey');
  FuncLoadError := not assigned(X509_REQ_get0_pubkey);
  if FuncLoadError then
  begin
    X509_REQ_get0_pubkey :=  @ERROR_X509_REQ_get0_pubkey;
  end;

  X509_REQ_get_X509_PUBKEY := LoadLibCryptoFunction('X509_REQ_get_X509_PUBKEY');
  FuncLoadError := not assigned(X509_REQ_get_X509_PUBKEY);
  if FuncLoadError then
  begin
    X509_REQ_get_X509_PUBKEY :=  @ERROR_X509_REQ_get_X509_PUBKEY;
  end;

  X509_REQ_extension_nid := LoadLibCryptoFunction('X509_REQ_extension_nid');
  FuncLoadError := not assigned(X509_REQ_extension_nid);
  if FuncLoadError then
  begin
    X509_REQ_extension_nid :=  @ERROR_X509_REQ_extension_nid;
  end;

  X509_REQ_get_extension_nids := LoadLibCryptoFunction('X509_REQ_get_extension_nids');
  FuncLoadError := not assigned(X509_REQ_get_extension_nids);
  if FuncLoadError then
  begin
    X509_REQ_get_extension_nids :=  @ERROR_X509_REQ_get_extension_nids;
  end;

  X509_REQ_set_extension_nids := LoadLibCryptoFunction('X509_REQ_set_extension_nids');
  FuncLoadError := not assigned(X509_REQ_set_extension_nids);
  if FuncLoadError then
  begin
    X509_REQ_set_extension_nids :=  @ERROR_X509_REQ_set_extension_nids;
  end;

  X509_REQ_get_attr_count := LoadLibCryptoFunction('X509_REQ_get_attr_count');
  FuncLoadError := not assigned(X509_REQ_get_attr_count);
  if FuncLoadError then
  begin
    X509_REQ_get_attr_count :=  @ERROR_X509_REQ_get_attr_count;
  end;

  X509_REQ_get_attr_by_NID := LoadLibCryptoFunction('X509_REQ_get_attr_by_NID');
  FuncLoadError := not assigned(X509_REQ_get_attr_by_NID);
  if FuncLoadError then
  begin
    X509_REQ_get_attr_by_NID :=  @ERROR_X509_REQ_get_attr_by_NID;
  end;

  X509_REQ_get_attr_by_OBJ := LoadLibCryptoFunction('X509_REQ_get_attr_by_OBJ');
  FuncLoadError := not assigned(X509_REQ_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    X509_REQ_get_attr_by_OBJ :=  @ERROR_X509_REQ_get_attr_by_OBJ;
  end;

  X509_REQ_get_attr := LoadLibCryptoFunction('X509_REQ_get_attr');
  FuncLoadError := not assigned(X509_REQ_get_attr);
  if FuncLoadError then
  begin
    X509_REQ_get_attr :=  @ERROR_X509_REQ_get_attr;
  end;

  X509_REQ_delete_attr := LoadLibCryptoFunction('X509_REQ_delete_attr');
  FuncLoadError := not assigned(X509_REQ_delete_attr);
  if FuncLoadError then
  begin
    X509_REQ_delete_attr :=  @ERROR_X509_REQ_delete_attr;
  end;

  X509_REQ_add1_attr := LoadLibCryptoFunction('X509_REQ_add1_attr');
  FuncLoadError := not assigned(X509_REQ_add1_attr);
  if FuncLoadError then
  begin
    X509_REQ_add1_attr :=  @ERROR_X509_REQ_add1_attr;
  end;

  X509_REQ_add1_attr_by_OBJ := LoadLibCryptoFunction('X509_REQ_add1_attr_by_OBJ');
  FuncLoadError := not assigned(X509_REQ_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    X509_REQ_add1_attr_by_OBJ :=  @ERROR_X509_REQ_add1_attr_by_OBJ;
  end;

  X509_REQ_add1_attr_by_NID := LoadLibCryptoFunction('X509_REQ_add1_attr_by_NID');
  FuncLoadError := not assigned(X509_REQ_add1_attr_by_NID);
  if FuncLoadError then
  begin
    X509_REQ_add1_attr_by_NID :=  @ERROR_X509_REQ_add1_attr_by_NID;
  end;

  X509_REQ_add1_attr_by_txt := LoadLibCryptoFunction('X509_REQ_add1_attr_by_txt');
  FuncLoadError := not assigned(X509_REQ_add1_attr_by_txt);
  if FuncLoadError then
  begin
    X509_REQ_add1_attr_by_txt :=  @ERROR_X509_REQ_add1_attr_by_txt;
  end;

  X509_CRL_set_version := LoadLibCryptoFunction('X509_CRL_set_version');
  FuncLoadError := not assigned(X509_CRL_set_version);
  if FuncLoadError then
  begin
    X509_CRL_set_version :=  @ERROR_X509_CRL_set_version;
  end;

  X509_CRL_set_issuer_name := LoadLibCryptoFunction('X509_CRL_set_issuer_name');
  FuncLoadError := not assigned(X509_CRL_set_issuer_name);
  if FuncLoadError then
  begin
    X509_CRL_set_issuer_name :=  @ERROR_X509_CRL_set_issuer_name;
  end;

  X509_CRL_set1_lastUpdate := LoadLibCryptoFunction('X509_CRL_set1_lastUpdate');
  FuncLoadError := not assigned(X509_CRL_set1_lastUpdate);
  if FuncLoadError then
  begin
    X509_CRL_set1_lastUpdate :=  @ERROR_X509_CRL_set1_lastUpdate;
  end;

  X509_CRL_set1_nextUpdate := LoadLibCryptoFunction('X509_CRL_set1_nextUpdate');
  FuncLoadError := not assigned(X509_CRL_set1_nextUpdate);
  if FuncLoadError then
  begin
    X509_CRL_set1_nextUpdate :=  @ERROR_X509_CRL_set1_nextUpdate;
  end;

  X509_CRL_sort := LoadLibCryptoFunction('X509_CRL_sort');
  FuncLoadError := not assigned(X509_CRL_sort);
  if FuncLoadError then
  begin
    X509_CRL_sort :=  @ERROR_X509_CRL_sort;
  end;

  X509_CRL_up_ref := LoadLibCryptoFunction('X509_CRL_up_ref');
  FuncLoadError := not assigned(X509_CRL_up_ref);
  if FuncLoadError then
  begin
    X509_CRL_up_ref :=  @ERROR_X509_CRL_up_ref;
  end;

  X509_CRL_get_version := LoadLibCryptoFunction('X509_CRL_get_version');
  FuncLoadError := not assigned(X509_CRL_get_version);
  if FuncLoadError then
  begin
    X509_CRL_get_version :=  @ERROR_X509_CRL_get_version;
  end;

  X509_CRL_get0_lastUpdate := LoadLibCryptoFunction('X509_CRL_get0_lastUpdate');
  FuncLoadError := not assigned(X509_CRL_get0_lastUpdate);
  if FuncLoadError then
  begin
    X509_CRL_get0_lastUpdate :=  @ERROR_X509_CRL_get0_lastUpdate;
  end;

  X509_CRL_get0_nextUpdate := LoadLibCryptoFunction('X509_CRL_get0_nextUpdate');
  FuncLoadError := not assigned(X509_CRL_get0_nextUpdate);
  if FuncLoadError then
  begin
    X509_CRL_get0_nextUpdate :=  @ERROR_X509_CRL_get0_nextUpdate;
  end;

  X509_CRL_get_issuer := LoadLibCryptoFunction('X509_CRL_get_issuer');
  FuncLoadError := not assigned(X509_CRL_get_issuer);
  if FuncLoadError then
  begin
    X509_CRL_get_issuer :=  @ERROR_X509_CRL_get_issuer;
  end;

  X509_CRL_get0_signature := LoadLibCryptoFunction('X509_CRL_get0_signature');
  FuncLoadError := not assigned(X509_CRL_get0_signature);
  if FuncLoadError then
  begin
    X509_CRL_get0_signature :=  @ERROR_X509_CRL_get0_signature;
  end;

  X509_CRL_get_signature_nid := LoadLibCryptoFunction('X509_CRL_get_signature_nid');
  FuncLoadError := not assigned(X509_CRL_get_signature_nid);
  if FuncLoadError then
  begin
    X509_CRL_get_signature_nid :=  @ERROR_X509_CRL_get_signature_nid;
  end;

  i2d_re_X509_CRL_tbs := LoadLibCryptoFunction('i2d_re_X509_CRL_tbs');
  FuncLoadError := not assigned(i2d_re_X509_CRL_tbs);
  if FuncLoadError then
  begin
    i2d_re_X509_CRL_tbs :=  @ERROR_i2d_re_X509_CRL_tbs;
  end;

  X509_REVOKED_get0_serialNumber := LoadLibCryptoFunction('X509_REVOKED_get0_serialNumber');
  FuncLoadError := not assigned(X509_REVOKED_get0_serialNumber);
  if FuncLoadError then
  begin
    X509_REVOKED_get0_serialNumber :=  @ERROR_X509_REVOKED_get0_serialNumber;
  end;

  X509_REVOKED_set_serialNumber := LoadLibCryptoFunction('X509_REVOKED_set_serialNumber');
  FuncLoadError := not assigned(X509_REVOKED_set_serialNumber);
  if FuncLoadError then
  begin
    X509_REVOKED_set_serialNumber :=  @ERROR_X509_REVOKED_set_serialNumber;
  end;

  X509_REVOKED_get0_revocationDate := LoadLibCryptoFunction('X509_REVOKED_get0_revocationDate');
  FuncLoadError := not assigned(X509_REVOKED_get0_revocationDate);
  if FuncLoadError then
  begin
    X509_REVOKED_get0_revocationDate :=  @ERROR_X509_REVOKED_get0_revocationDate;
  end;

  X509_REVOKED_set_revocationDate := LoadLibCryptoFunction('X509_REVOKED_set_revocationDate');
  FuncLoadError := not assigned(X509_REVOKED_set_revocationDate);
  if FuncLoadError then
  begin
    X509_REVOKED_set_revocationDate :=  @ERROR_X509_REVOKED_set_revocationDate;
  end;

  X509_CRL_diff := LoadLibCryptoFunction('X509_CRL_diff');
  FuncLoadError := not assigned(X509_CRL_diff);
  if FuncLoadError then
  begin
    X509_CRL_diff :=  @ERROR_X509_CRL_diff;
  end;

  X509_REQ_check_private_key := LoadLibCryptoFunction('X509_REQ_check_private_key');
  FuncLoadError := not assigned(X509_REQ_check_private_key);
  if FuncLoadError then
  begin
    X509_REQ_check_private_key :=  @ERROR_X509_REQ_check_private_key;
  end;

  X509_check_private_key := LoadLibCryptoFunction('X509_check_private_key');
  FuncLoadError := not assigned(X509_check_private_key);
  if FuncLoadError then
  begin
    X509_check_private_key :=  @ERROR_X509_check_private_key;
  end;

  X509_CRL_check_suiteb := LoadLibCryptoFunction('X509_CRL_check_suiteb');
  FuncLoadError := not assigned(X509_CRL_check_suiteb);
  if FuncLoadError then
  begin
    X509_CRL_check_suiteb :=  @ERROR_X509_CRL_check_suiteb;
  end;

  X509_issuer_and_serial_cmp := LoadLibCryptoFunction('X509_issuer_and_serial_cmp');
  FuncLoadError := not assigned(X509_issuer_and_serial_cmp);
  if FuncLoadError then
  begin
    X509_issuer_and_serial_cmp :=  @ERROR_X509_issuer_and_serial_cmp;
  end;

  X509_issuer_and_serial_hash := LoadLibCryptoFunction('X509_issuer_and_serial_hash');
  FuncLoadError := not assigned(X509_issuer_and_serial_hash);
  if FuncLoadError then
  begin
    X509_issuer_and_serial_hash :=  @ERROR_X509_issuer_and_serial_hash;
  end;

  X509_issuer_name_cmp := LoadLibCryptoFunction('X509_issuer_name_cmp');
  FuncLoadError := not assigned(X509_issuer_name_cmp);
  if FuncLoadError then
  begin
    X509_issuer_name_cmp :=  @ERROR_X509_issuer_name_cmp;
  end;

  X509_issuer_name_hash := LoadLibCryptoFunction('X509_issuer_name_hash');
  FuncLoadError := not assigned(X509_issuer_name_hash);
  if FuncLoadError then
  begin
    X509_issuer_name_hash :=  @ERROR_X509_issuer_name_hash;
  end;

  X509_subject_name_cmp := LoadLibCryptoFunction('X509_subject_name_cmp');
  FuncLoadError := not assigned(X509_subject_name_cmp);
  if FuncLoadError then
  begin
    X509_subject_name_cmp :=  @ERROR_X509_subject_name_cmp;
  end;

  X509_subject_name_hash := LoadLibCryptoFunction('X509_subject_name_hash');
  FuncLoadError := not assigned(X509_subject_name_hash);
  if FuncLoadError then
  begin
    X509_subject_name_hash :=  @ERROR_X509_subject_name_hash;
  end;

  X509_cmp := LoadLibCryptoFunction('X509_cmp');
  FuncLoadError := not assigned(X509_cmp);
  if FuncLoadError then
  begin
    X509_cmp :=  @ERROR_X509_cmp;
  end;

  X509_NAME_cmp := LoadLibCryptoFunction('X509_NAME_cmp');
  FuncLoadError := not assigned(X509_NAME_cmp);
  if FuncLoadError then
  begin
    X509_NAME_cmp :=  @ERROR_X509_NAME_cmp;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_NAME_hash := LoadLibCryptoFunction('X509_NAME_hash');
  FuncLoadError := not assigned(X509_NAME_hash);
  if FuncLoadError then
  begin
    X509_NAME_hash := @COMPAT_X509_NAME_hash;
    if X509_NAME_hash_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('X509_NAME_hash');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_NAME_hash_old := LoadLibCryptoFunction('X509_NAME_hash_old');
  FuncLoadError := not assigned(X509_NAME_hash_old);
  if FuncLoadError then
  begin
    X509_NAME_hash_old :=  @ERROR_X509_NAME_hash_old;
  end;

  X509_CRL_cmp := LoadLibCryptoFunction('X509_CRL_cmp');
  FuncLoadError := not assigned(X509_CRL_cmp);
  if FuncLoadError then
  begin
    X509_CRL_cmp :=  @ERROR_X509_CRL_cmp;
  end;

  X509_CRL_match := LoadLibCryptoFunction('X509_CRL_match');
  FuncLoadError := not assigned(X509_CRL_match);
  if FuncLoadError then
  begin
    X509_CRL_match :=  @ERROR_X509_CRL_match;
  end;

  X509_aux_print := LoadLibCryptoFunction('X509_aux_print');
  FuncLoadError := not assigned(X509_aux_print);
  if FuncLoadError then
  begin
    X509_aux_print :=  @ERROR_X509_aux_print;
  end;

  X509_NAME_print := LoadLibCryptoFunction('X509_NAME_print');
  FuncLoadError := not assigned(X509_NAME_print);
  if FuncLoadError then
  begin
    X509_NAME_print :=  @ERROR_X509_NAME_print;
  end;

  X509_NAME_print_ex := LoadLibCryptoFunction('X509_NAME_print_ex');
  FuncLoadError := not assigned(X509_NAME_print_ex);
  if FuncLoadError then
  begin
    X509_NAME_print_ex :=  @ERROR_X509_NAME_print_ex;
  end;

  X509_print_ex := LoadLibCryptoFunction('X509_print_ex');
  FuncLoadError := not assigned(X509_print_ex);
  if FuncLoadError then
  begin
    X509_print_ex :=  @ERROR_X509_print_ex;
  end;

  X509_print := LoadLibCryptoFunction('X509_print');
  FuncLoadError := not assigned(X509_print);
  if FuncLoadError then
  begin
    X509_print :=  @ERROR_X509_print;
  end;

  X509_ocspid_print := LoadLibCryptoFunction('X509_ocspid_print');
  FuncLoadError := not assigned(X509_ocspid_print);
  if FuncLoadError then
  begin
    X509_ocspid_print :=  @ERROR_X509_ocspid_print;
  end;

  X509_CRL_print_ex := LoadLibCryptoFunction('X509_CRL_print_ex');
  FuncLoadError := not assigned(X509_CRL_print_ex);
  if FuncLoadError then
  begin
    X509_CRL_print_ex :=  @ERROR_X509_CRL_print_ex;
  end;

  X509_CRL_print := LoadLibCryptoFunction('X509_CRL_print');
  FuncLoadError := not assigned(X509_CRL_print);
  if FuncLoadError then
  begin
    X509_CRL_print :=  @ERROR_X509_CRL_print;
  end;

  X509_REQ_print_ex := LoadLibCryptoFunction('X509_REQ_print_ex');
  FuncLoadError := not assigned(X509_REQ_print_ex);
  if FuncLoadError then
  begin
    X509_REQ_print_ex :=  @ERROR_X509_REQ_print_ex;
  end;

  X509_REQ_print := LoadLibCryptoFunction('X509_REQ_print');
  FuncLoadError := not assigned(X509_REQ_print);
  if FuncLoadError then
  begin
    X509_REQ_print :=  @ERROR_X509_REQ_print;
  end;

  X509_NAME_entry_count := LoadLibCryptoFunction('X509_NAME_entry_count');
  FuncLoadError := not assigned(X509_NAME_entry_count);
  if FuncLoadError then
  begin
    X509_NAME_entry_count :=  @ERROR_X509_NAME_entry_count;
  end;

  X509_NAME_get_text_by_NID := LoadLibCryptoFunction('X509_NAME_get_text_by_NID');
  FuncLoadError := not assigned(X509_NAME_get_text_by_NID);
  if FuncLoadError then
  begin
    X509_NAME_get_text_by_NID :=  @ERROR_X509_NAME_get_text_by_NID;
  end;

  X509_NAME_get_text_by_OBJ := LoadLibCryptoFunction('X509_NAME_get_text_by_OBJ');
  FuncLoadError := not assigned(X509_NAME_get_text_by_OBJ);
  if FuncLoadError then
  begin
    X509_NAME_get_text_by_OBJ :=  @ERROR_X509_NAME_get_text_by_OBJ;
  end;

  X509_NAME_get_index_by_NID := LoadLibCryptoFunction('X509_NAME_get_index_by_NID');
  FuncLoadError := not assigned(X509_NAME_get_index_by_NID);
  if FuncLoadError then
  begin
    X509_NAME_get_index_by_NID :=  @ERROR_X509_NAME_get_index_by_NID;
  end;

  X509_NAME_get_index_by_OBJ := LoadLibCryptoFunction('X509_NAME_get_index_by_OBJ');
  FuncLoadError := not assigned(X509_NAME_get_index_by_OBJ);
  if FuncLoadError then
  begin
    X509_NAME_get_index_by_OBJ :=  @ERROR_X509_NAME_get_index_by_OBJ;
  end;

  X509_NAME_get_entry := LoadLibCryptoFunction('X509_NAME_get_entry');
  FuncLoadError := not assigned(X509_NAME_get_entry);
  if FuncLoadError then
  begin
    X509_NAME_get_entry :=  @ERROR_X509_NAME_get_entry;
  end;

  X509_NAME_delete_entry := LoadLibCryptoFunction('X509_NAME_delete_entry');
  FuncLoadError := not assigned(X509_NAME_delete_entry);
  if FuncLoadError then
  begin
    X509_NAME_delete_entry :=  @ERROR_X509_NAME_delete_entry;
  end;

  X509_NAME_add_entry := LoadLibCryptoFunction('X509_NAME_add_entry');
  FuncLoadError := not assigned(X509_NAME_add_entry);
  if FuncLoadError then
  begin
    X509_NAME_add_entry :=  @ERROR_X509_NAME_add_entry;
  end;

  X509_NAME_add_entry_by_OBJ := LoadLibCryptoFunction('X509_NAME_add_entry_by_OBJ');
  FuncLoadError := not assigned(X509_NAME_add_entry_by_OBJ);
  if FuncLoadError then
  begin
    X509_NAME_add_entry_by_OBJ :=  @ERROR_X509_NAME_add_entry_by_OBJ;
  end;

  X509_NAME_add_entry_by_NID := LoadLibCryptoFunction('X509_NAME_add_entry_by_NID');
  FuncLoadError := not assigned(X509_NAME_add_entry_by_NID);
  if FuncLoadError then
  begin
    X509_NAME_add_entry_by_NID :=  @ERROR_X509_NAME_add_entry_by_NID;
  end;

  X509_NAME_ENTRY_create_by_txt := LoadLibCryptoFunction('X509_NAME_ENTRY_create_by_txt');
  FuncLoadError := not assigned(X509_NAME_ENTRY_create_by_txt);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_create_by_txt :=  @ERROR_X509_NAME_ENTRY_create_by_txt;
  end;

  X509_NAME_ENTRY_create_by_NID := LoadLibCryptoFunction('X509_NAME_ENTRY_create_by_NID');
  FuncLoadError := not assigned(X509_NAME_ENTRY_create_by_NID);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_create_by_NID :=  @ERROR_X509_NAME_ENTRY_create_by_NID;
  end;

  X509_NAME_add_entry_by_txt := LoadLibCryptoFunction('X509_NAME_add_entry_by_txt');
  FuncLoadError := not assigned(X509_NAME_add_entry_by_txt);
  if FuncLoadError then
  begin
    X509_NAME_add_entry_by_txt :=  @ERROR_X509_NAME_add_entry_by_txt;
  end;

  X509_NAME_ENTRY_create_by_OBJ := LoadLibCryptoFunction('X509_NAME_ENTRY_create_by_OBJ');
  FuncLoadError := not assigned(X509_NAME_ENTRY_create_by_OBJ);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_create_by_OBJ :=  @ERROR_X509_NAME_ENTRY_create_by_OBJ;
  end;

  X509_NAME_ENTRY_set_object := LoadLibCryptoFunction('X509_NAME_ENTRY_set_object');
  FuncLoadError := not assigned(X509_NAME_ENTRY_set_object);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_set_object :=  @ERROR_X509_NAME_ENTRY_set_object;
  end;

  X509_NAME_ENTRY_set_data := LoadLibCryptoFunction('X509_NAME_ENTRY_set_data');
  FuncLoadError := not assigned(X509_NAME_ENTRY_set_data);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_set_data :=  @ERROR_X509_NAME_ENTRY_set_data;
  end;

  X509_NAME_ENTRY_get_object := LoadLibCryptoFunction('X509_NAME_ENTRY_get_object');
  FuncLoadError := not assigned(X509_NAME_ENTRY_get_object);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_get_object :=  @ERROR_X509_NAME_ENTRY_get_object;
  end;

  X509_NAME_ENTRY_get_data := LoadLibCryptoFunction('X509_NAME_ENTRY_get_data');
  FuncLoadError := not assigned(X509_NAME_ENTRY_get_data);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_get_data :=  @ERROR_X509_NAME_ENTRY_get_data;
  end;

  X509_NAME_ENTRY_set := LoadLibCryptoFunction('X509_NAME_ENTRY_set');
  FuncLoadError := not assigned(X509_NAME_ENTRY_set);
  if FuncLoadError then
  begin
    X509_NAME_ENTRY_set :=  @ERROR_X509_NAME_ENTRY_set;
  end;

  X509_NAME_get0_der := LoadLibCryptoFunction('X509_NAME_get0_der');
  FuncLoadError := not assigned(X509_NAME_get0_der);
  if FuncLoadError then
  begin
    X509_NAME_get0_der :=  @ERROR_X509_NAME_get0_der;
  end;

  X509_get_ext_count := LoadLibCryptoFunction('X509_get_ext_count');
  FuncLoadError := not assigned(X509_get_ext_count);
  if FuncLoadError then
  begin
    X509_get_ext_count :=  @ERROR_X509_get_ext_count;
  end;

  X509_get_ext_by_NID := LoadLibCryptoFunction('X509_get_ext_by_NID');
  FuncLoadError := not assigned(X509_get_ext_by_NID);
  if FuncLoadError then
  begin
    X509_get_ext_by_NID :=  @ERROR_X509_get_ext_by_NID;
  end;

  X509_get_ext_by_OBJ := LoadLibCryptoFunction('X509_get_ext_by_OBJ');
  FuncLoadError := not assigned(X509_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    X509_get_ext_by_OBJ :=  @ERROR_X509_get_ext_by_OBJ;
  end;

  X509_get_ext_by_critical := LoadLibCryptoFunction('X509_get_ext_by_critical');
  FuncLoadError := not assigned(X509_get_ext_by_critical);
  if FuncLoadError then
  begin
    X509_get_ext_by_critical :=  @ERROR_X509_get_ext_by_critical;
  end;

  X509_get_ext := LoadLibCryptoFunction('X509_get_ext');
  FuncLoadError := not assigned(X509_get_ext);
  if FuncLoadError then
  begin
    X509_get_ext :=  @ERROR_X509_get_ext;
  end;

  X509_delete_ext := LoadLibCryptoFunction('X509_delete_ext');
  FuncLoadError := not assigned(X509_delete_ext);
  if FuncLoadError then
  begin
    X509_delete_ext :=  @ERROR_X509_delete_ext;
  end;

  X509_add_ext := LoadLibCryptoFunction('X509_add_ext');
  FuncLoadError := not assigned(X509_add_ext);
  if FuncLoadError then
  begin
    X509_add_ext :=  @ERROR_X509_add_ext;
  end;

  X509_get_ext_d2i := LoadLibCryptoFunction('X509_get_ext_d2i');
  FuncLoadError := not assigned(X509_get_ext_d2i);
  if FuncLoadError then
  begin
    X509_get_ext_d2i :=  @ERROR_X509_get_ext_d2i;
  end;

  X509_add1_ext_i2d := LoadLibCryptoFunction('X509_add1_ext_i2d');
  FuncLoadError := not assigned(X509_add1_ext_i2d);
  if FuncLoadError then
  begin
    X509_add1_ext_i2d :=  @ERROR_X509_add1_ext_i2d;
  end;

  X509_CRL_get_ext_count := LoadLibCryptoFunction('X509_CRL_get_ext_count');
  FuncLoadError := not assigned(X509_CRL_get_ext_count);
  if FuncLoadError then
  begin
    X509_CRL_get_ext_count :=  @ERROR_X509_CRL_get_ext_count;
  end;

  X509_CRL_get_ext_by_NID := LoadLibCryptoFunction('X509_CRL_get_ext_by_NID');
  FuncLoadError := not assigned(X509_CRL_get_ext_by_NID);
  if FuncLoadError then
  begin
    X509_CRL_get_ext_by_NID :=  @ERROR_X509_CRL_get_ext_by_NID;
  end;

  X509_CRL_get_ext_by_OBJ := LoadLibCryptoFunction('X509_CRL_get_ext_by_OBJ');
  FuncLoadError := not assigned(X509_CRL_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    X509_CRL_get_ext_by_OBJ :=  @ERROR_X509_CRL_get_ext_by_OBJ;
  end;

  X509_CRL_get_ext_by_critical := LoadLibCryptoFunction('X509_CRL_get_ext_by_critical');
  FuncLoadError := not assigned(X509_CRL_get_ext_by_critical);
  if FuncLoadError then
  begin
    X509_CRL_get_ext_by_critical :=  @ERROR_X509_CRL_get_ext_by_critical;
  end;

  X509_CRL_get_ext := LoadLibCryptoFunction('X509_CRL_get_ext');
  FuncLoadError := not assigned(X509_CRL_get_ext);
  if FuncLoadError then
  begin
    X509_CRL_get_ext :=  @ERROR_X509_CRL_get_ext;
  end;

  X509_CRL_delete_ext := LoadLibCryptoFunction('X509_CRL_delete_ext');
  FuncLoadError := not assigned(X509_CRL_delete_ext);
  if FuncLoadError then
  begin
    X509_CRL_delete_ext :=  @ERROR_X509_CRL_delete_ext;
  end;

  X509_CRL_add_ext := LoadLibCryptoFunction('X509_CRL_add_ext');
  FuncLoadError := not assigned(X509_CRL_add_ext);
  if FuncLoadError then
  begin
    X509_CRL_add_ext :=  @ERROR_X509_CRL_add_ext;
  end;

  X509_CRL_get_ext_d2i := LoadLibCryptoFunction('X509_CRL_get_ext_d2i');
  FuncLoadError := not assigned(X509_CRL_get_ext_d2i);
  if FuncLoadError then
  begin
    X509_CRL_get_ext_d2i :=  @ERROR_X509_CRL_get_ext_d2i;
  end;

  X509_CRL_add1_ext_i2d := LoadLibCryptoFunction('X509_CRL_add1_ext_i2d');
  FuncLoadError := not assigned(X509_CRL_add1_ext_i2d);
  if FuncLoadError then
  begin
    X509_CRL_add1_ext_i2d :=  @ERROR_X509_CRL_add1_ext_i2d;
  end;

  X509_REVOKED_get_ext_count := LoadLibCryptoFunction('X509_REVOKED_get_ext_count');
  FuncLoadError := not assigned(X509_REVOKED_get_ext_count);
  if FuncLoadError then
  begin
    X509_REVOKED_get_ext_count :=  @ERROR_X509_REVOKED_get_ext_count;
  end;

  X509_REVOKED_get_ext_by_NID := LoadLibCryptoFunction('X509_REVOKED_get_ext_by_NID');
  FuncLoadError := not assigned(X509_REVOKED_get_ext_by_NID);
  if FuncLoadError then
  begin
    X509_REVOKED_get_ext_by_NID :=  @ERROR_X509_REVOKED_get_ext_by_NID;
  end;

  X509_REVOKED_get_ext_by_OBJ := LoadLibCryptoFunction('X509_REVOKED_get_ext_by_OBJ');
  FuncLoadError := not assigned(X509_REVOKED_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    X509_REVOKED_get_ext_by_OBJ :=  @ERROR_X509_REVOKED_get_ext_by_OBJ;
  end;

  X509_REVOKED_get_ext_by_critical := LoadLibCryptoFunction('X509_REVOKED_get_ext_by_critical');
  FuncLoadError := not assigned(X509_REVOKED_get_ext_by_critical);
  if FuncLoadError then
  begin
    X509_REVOKED_get_ext_by_critical :=  @ERROR_X509_REVOKED_get_ext_by_critical;
  end;

  X509_REVOKED_get_ext := LoadLibCryptoFunction('X509_REVOKED_get_ext');
  FuncLoadError := not assigned(X509_REVOKED_get_ext);
  if FuncLoadError then
  begin
    X509_REVOKED_get_ext :=  @ERROR_X509_REVOKED_get_ext;
  end;

  X509_REVOKED_delete_ext := LoadLibCryptoFunction('X509_REVOKED_delete_ext');
  FuncLoadError := not assigned(X509_REVOKED_delete_ext);
  if FuncLoadError then
  begin
    X509_REVOKED_delete_ext :=  @ERROR_X509_REVOKED_delete_ext;
  end;

  X509_REVOKED_add_ext := LoadLibCryptoFunction('X509_REVOKED_add_ext');
  FuncLoadError := not assigned(X509_REVOKED_add_ext);
  if FuncLoadError then
  begin
    X509_REVOKED_add_ext :=  @ERROR_X509_REVOKED_add_ext;
  end;

  X509_REVOKED_get_ext_d2i := LoadLibCryptoFunction('X509_REVOKED_get_ext_d2i');
  FuncLoadError := not assigned(X509_REVOKED_get_ext_d2i);
  if FuncLoadError then
  begin
    X509_REVOKED_get_ext_d2i :=  @ERROR_X509_REVOKED_get_ext_d2i;
  end;

  X509_REVOKED_add1_ext_i2d := LoadLibCryptoFunction('X509_REVOKED_add1_ext_i2d');
  FuncLoadError := not assigned(X509_REVOKED_add1_ext_i2d);
  if FuncLoadError then
  begin
    X509_REVOKED_add1_ext_i2d :=  @ERROR_X509_REVOKED_add1_ext_i2d;
  end;

  X509_EXTENSION_create_by_NID := LoadLibCryptoFunction('X509_EXTENSION_create_by_NID');
  FuncLoadError := not assigned(X509_EXTENSION_create_by_NID);
  if FuncLoadError then
  begin
    X509_EXTENSION_create_by_NID :=  @ERROR_X509_EXTENSION_create_by_NID;
  end;

  X509_EXTENSION_create_by_OBJ := LoadLibCryptoFunction('X509_EXTENSION_create_by_OBJ');
  FuncLoadError := not assigned(X509_EXTENSION_create_by_OBJ);
  if FuncLoadError then
  begin
    X509_EXTENSION_create_by_OBJ :=  @ERROR_X509_EXTENSION_create_by_OBJ;
  end;

  X509_EXTENSION_set_object := LoadLibCryptoFunction('X509_EXTENSION_set_object');
  FuncLoadError := not assigned(X509_EXTENSION_set_object);
  if FuncLoadError then
  begin
    X509_EXTENSION_set_object :=  @ERROR_X509_EXTENSION_set_object;
  end;

  X509_EXTENSION_set_critical := LoadLibCryptoFunction('X509_EXTENSION_set_critical');
  FuncLoadError := not assigned(X509_EXTENSION_set_critical);
  if FuncLoadError then
  begin
    X509_EXTENSION_set_critical :=  @ERROR_X509_EXTENSION_set_critical;
  end;

  X509_EXTENSION_set_data := LoadLibCryptoFunction('X509_EXTENSION_set_data');
  FuncLoadError := not assigned(X509_EXTENSION_set_data);
  if FuncLoadError then
  begin
    X509_EXTENSION_set_data :=  @ERROR_X509_EXTENSION_set_data;
  end;

  X509_EXTENSION_get_object := LoadLibCryptoFunction('X509_EXTENSION_get_object');
  FuncLoadError := not assigned(X509_EXTENSION_get_object);
  if FuncLoadError then
  begin
    X509_EXTENSION_get_object :=  @ERROR_X509_EXTENSION_get_object;
  end;

  X509_EXTENSION_get_data := LoadLibCryptoFunction('X509_EXTENSION_get_data');
  FuncLoadError := not assigned(X509_EXTENSION_get_data);
  if FuncLoadError then
  begin
    X509_EXTENSION_get_data :=  @ERROR_X509_EXTENSION_get_data;
  end;

  X509_EXTENSION_get_critical := LoadLibCryptoFunction('X509_EXTENSION_get_critical');
  FuncLoadError := not assigned(X509_EXTENSION_get_critical);
  if FuncLoadError then
  begin
    X509_EXTENSION_get_critical :=  @ERROR_X509_EXTENSION_get_critical;
  end;

  X509_ATTRIBUTE_create_by_NID := LoadLibCryptoFunction('X509_ATTRIBUTE_create_by_NID');
  FuncLoadError := not assigned(X509_ATTRIBUTE_create_by_NID);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_create_by_NID :=  @ERROR_X509_ATTRIBUTE_create_by_NID;
  end;

  X509_ATTRIBUTE_create_by_OBJ := LoadLibCryptoFunction('X509_ATTRIBUTE_create_by_OBJ');
  FuncLoadError := not assigned(X509_ATTRIBUTE_create_by_OBJ);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_create_by_OBJ :=  @ERROR_X509_ATTRIBUTE_create_by_OBJ;
  end;

  X509_ATTRIBUTE_create_by_txt := LoadLibCryptoFunction('X509_ATTRIBUTE_create_by_txt');
  FuncLoadError := not assigned(X509_ATTRIBUTE_create_by_txt);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_create_by_txt :=  @ERROR_X509_ATTRIBUTE_create_by_txt;
  end;

  X509_ATTRIBUTE_set1_object := LoadLibCryptoFunction('X509_ATTRIBUTE_set1_object');
  FuncLoadError := not assigned(X509_ATTRIBUTE_set1_object);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_set1_object :=  @ERROR_X509_ATTRIBUTE_set1_object;
  end;

  X509_ATTRIBUTE_set1_data := LoadLibCryptoFunction('X509_ATTRIBUTE_set1_data');
  FuncLoadError := not assigned(X509_ATTRIBUTE_set1_data);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_set1_data :=  @ERROR_X509_ATTRIBUTE_set1_data;
  end;

  X509_ATTRIBUTE_get0_data := LoadLibCryptoFunction('X509_ATTRIBUTE_get0_data');
  FuncLoadError := not assigned(X509_ATTRIBUTE_get0_data);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_get0_data :=  @ERROR_X509_ATTRIBUTE_get0_data;
  end;

  X509_ATTRIBUTE_count := LoadLibCryptoFunction('X509_ATTRIBUTE_count');
  FuncLoadError := not assigned(X509_ATTRIBUTE_count);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_count :=  @ERROR_X509_ATTRIBUTE_count;
  end;

  X509_ATTRIBUTE_get0_object := LoadLibCryptoFunction('X509_ATTRIBUTE_get0_object');
  FuncLoadError := not assigned(X509_ATTRIBUTE_get0_object);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_get0_object :=  @ERROR_X509_ATTRIBUTE_get0_object;
  end;

  X509_ATTRIBUTE_get0_type := LoadLibCryptoFunction('X509_ATTRIBUTE_get0_type');
  FuncLoadError := not assigned(X509_ATTRIBUTE_get0_type);
  if FuncLoadError then
  begin
    X509_ATTRIBUTE_get0_type :=  @ERROR_X509_ATTRIBUTE_get0_type;
  end;

  EVP_PKEY_get_attr_count := LoadLibCryptoFunction('EVP_PKEY_get_attr_count');
  FuncLoadError := not assigned(EVP_PKEY_get_attr_count);
  if FuncLoadError then
  begin
    EVP_PKEY_get_attr_count :=  @ERROR_EVP_PKEY_get_attr_count;
  end;

  EVP_PKEY_get_attr_by_NID := LoadLibCryptoFunction('EVP_PKEY_get_attr_by_NID');
  FuncLoadError := not assigned(EVP_PKEY_get_attr_by_NID);
  if FuncLoadError then
  begin
    EVP_PKEY_get_attr_by_NID :=  @ERROR_EVP_PKEY_get_attr_by_NID;
  end;

  EVP_PKEY_get_attr_by_OBJ := LoadLibCryptoFunction('EVP_PKEY_get_attr_by_OBJ');
  FuncLoadError := not assigned(EVP_PKEY_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    EVP_PKEY_get_attr_by_OBJ :=  @ERROR_EVP_PKEY_get_attr_by_OBJ;
  end;

  EVP_PKEY_get_attr := LoadLibCryptoFunction('EVP_PKEY_get_attr');
  FuncLoadError := not assigned(EVP_PKEY_get_attr);
  if FuncLoadError then
  begin
    EVP_PKEY_get_attr :=  @ERROR_EVP_PKEY_get_attr;
  end;

  EVP_PKEY_delete_attr := LoadLibCryptoFunction('EVP_PKEY_delete_attr');
  FuncLoadError := not assigned(EVP_PKEY_delete_attr);
  if FuncLoadError then
  begin
    EVP_PKEY_delete_attr :=  @ERROR_EVP_PKEY_delete_attr;
  end;

  EVP_PKEY_add1_attr := LoadLibCryptoFunction('EVP_PKEY_add1_attr');
  FuncLoadError := not assigned(EVP_PKEY_add1_attr);
  if FuncLoadError then
  begin
    EVP_PKEY_add1_attr :=  @ERROR_EVP_PKEY_add1_attr;
  end;

  EVP_PKEY_add1_attr_by_OBJ := LoadLibCryptoFunction('EVP_PKEY_add1_attr_by_OBJ');
  FuncLoadError := not assigned(EVP_PKEY_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    EVP_PKEY_add1_attr_by_OBJ :=  @ERROR_EVP_PKEY_add1_attr_by_OBJ;
  end;

  EVP_PKEY_add1_attr_by_NID := LoadLibCryptoFunction('EVP_PKEY_add1_attr_by_NID');
  FuncLoadError := not assigned(EVP_PKEY_add1_attr_by_NID);
  if FuncLoadError then
  begin
    EVP_PKEY_add1_attr_by_NID :=  @ERROR_EVP_PKEY_add1_attr_by_NID;
  end;

  EVP_PKEY_add1_attr_by_txt := LoadLibCryptoFunction('EVP_PKEY_add1_attr_by_txt');
  FuncLoadError := not assigned(EVP_PKEY_add1_attr_by_txt);
  if FuncLoadError then
  begin
    EVP_PKEY_add1_attr_by_txt :=  @ERROR_EVP_PKEY_add1_attr_by_txt;
  end;

  X509_verify_cert := LoadLibCryptoFunction('X509_verify_cert');
  FuncLoadError := not assigned(X509_verify_cert);
  if FuncLoadError then
  begin
    X509_verify_cert :=  @ERROR_X509_verify_cert;
  end;

  PKCS5_pbe_set0_algor := LoadLibCryptoFunction('PKCS5_pbe_set0_algor');
  FuncLoadError := not assigned(PKCS5_pbe_set0_algor);
  if FuncLoadError then
  begin
    PKCS5_pbe_set0_algor :=  @ERROR_PKCS5_pbe_set0_algor;
  end;

  PKCS5_pbe_set := LoadLibCryptoFunction('PKCS5_pbe_set');
  FuncLoadError := not assigned(PKCS5_pbe_set);
  if FuncLoadError then
  begin
    PKCS5_pbe_set :=  @ERROR_PKCS5_pbe_set;
  end;

  PKCS5_pbe2_set := LoadLibCryptoFunction('PKCS5_pbe2_set');
  FuncLoadError := not assigned(PKCS5_pbe2_set);
  if FuncLoadError then
  begin
    PKCS5_pbe2_set :=  @ERROR_PKCS5_pbe2_set;
  end;

  PKCS5_pbe2_set_iv := LoadLibCryptoFunction('PKCS5_pbe2_set_iv');
  FuncLoadError := not assigned(PKCS5_pbe2_set_iv);
  if FuncLoadError then
  begin
    PKCS5_pbe2_set_iv :=  @ERROR_PKCS5_pbe2_set_iv;
  end;

  PKCS5_pbe2_set_scrypt := LoadLibCryptoFunction('PKCS5_pbe2_set_scrypt');
  FuncLoadError := not assigned(PKCS5_pbe2_set_scrypt);
  if FuncLoadError then
  begin
    PKCS5_pbe2_set_scrypt :=  @ERROR_PKCS5_pbe2_set_scrypt;
  end;

  PKCS5_pbkdf2_set := LoadLibCryptoFunction('PKCS5_pbkdf2_set');
  FuncLoadError := not assigned(PKCS5_pbkdf2_set);
  if FuncLoadError then
  begin
    PKCS5_pbkdf2_set :=  @ERROR_PKCS5_pbkdf2_set;
  end;

  EVP_PKCS82PKEY := LoadLibCryptoFunction('EVP_PKCS82PKEY');
  FuncLoadError := not assigned(EVP_PKCS82PKEY);
  if FuncLoadError then
  begin
    EVP_PKCS82PKEY :=  @ERROR_EVP_PKCS82PKEY;
  end;

  EVP_PKEY2PKCS8 := LoadLibCryptoFunction('EVP_PKEY2PKCS8');
  FuncLoadError := not assigned(EVP_PKEY2PKCS8);
  if FuncLoadError then
  begin
    EVP_PKEY2PKCS8 :=  @ERROR_EVP_PKEY2PKCS8;
  end;

  PKCS8_pkey_set0 := LoadLibCryptoFunction('PKCS8_pkey_set0');
  FuncLoadError := not assigned(PKCS8_pkey_set0);
  if FuncLoadError then
  begin
    PKCS8_pkey_set0 :=  @ERROR_PKCS8_pkey_set0;
  end;

  PKCS8_pkey_get0 := LoadLibCryptoFunction('PKCS8_pkey_get0');
  FuncLoadError := not assigned(PKCS8_pkey_get0);
  if FuncLoadError then
  begin
    PKCS8_pkey_get0 :=  @ERROR_PKCS8_pkey_get0;
  end;

  PKCS8_pkey_add1_attr_by_NID := LoadLibCryptoFunction('PKCS8_pkey_add1_attr_by_NID');
  FuncLoadError := not assigned(PKCS8_pkey_add1_attr_by_NID);
  if FuncLoadError then
  begin
    PKCS8_pkey_add1_attr_by_NID :=  @ERROR_PKCS8_pkey_add1_attr_by_NID;
  end;

  X509_PUBKEY_set0_param := LoadLibCryptoFunction('X509_PUBKEY_set0_param');
  FuncLoadError := not assigned(X509_PUBKEY_set0_param);
  if FuncLoadError then
  begin
    X509_PUBKEY_set0_param :=  @ERROR_X509_PUBKEY_set0_param;
  end;

  X509_PUBKEY_get0_param := LoadLibCryptoFunction('X509_PUBKEY_get0_param');
  FuncLoadError := not assigned(X509_PUBKEY_get0_param);
  if FuncLoadError then
  begin
    X509_PUBKEY_get0_param :=  @ERROR_X509_PUBKEY_get0_param;
  end;

  X509_check_trust := LoadLibCryptoFunction('X509_check_trust');
  FuncLoadError := not assigned(X509_check_trust);
  if FuncLoadError then
  begin
    X509_check_trust :=  @ERROR_X509_check_trust;
  end;

  X509_TRUST_get_count := LoadLibCryptoFunction('X509_TRUST_get_count');
  FuncLoadError := not assigned(X509_TRUST_get_count);
  if FuncLoadError then
  begin
    X509_TRUST_get_count :=  @ERROR_X509_TRUST_get_count;
  end;

  X509_TRUST_get0 := LoadLibCryptoFunction('X509_TRUST_get0');
  FuncLoadError := not assigned(X509_TRUST_get0);
  if FuncLoadError then
  begin
    X509_TRUST_get0 :=  @ERROR_X509_TRUST_get0;
  end;

  X509_TRUST_get_by_id := LoadLibCryptoFunction('X509_TRUST_get_by_id');
  FuncLoadError := not assigned(X509_TRUST_get_by_id);
  if FuncLoadError then
  begin
    X509_TRUST_get_by_id :=  @ERROR_X509_TRUST_get_by_id;
  end;

  X509_TRUST_cleanup := LoadLibCryptoFunction('X509_TRUST_cleanup');
  FuncLoadError := not assigned(X509_TRUST_cleanup);
  if FuncLoadError then
  begin
    X509_TRUST_cleanup :=  @ERROR_X509_TRUST_cleanup;
  end;

  X509_TRUST_get_flags := LoadLibCryptoFunction('X509_TRUST_get_flags');
  FuncLoadError := not assigned(X509_TRUST_get_flags);
  if FuncLoadError then
  begin
    X509_TRUST_get_flags :=  @ERROR_X509_TRUST_get_flags;
  end;

  X509_TRUST_get0_name := LoadLibCryptoFunction('X509_TRUST_get0_name');
  FuncLoadError := not assigned(X509_TRUST_get0_name);
  if FuncLoadError then
  begin
    X509_TRUST_get0_name :=  @ERROR_X509_TRUST_get0_name;
  end;

  X509_TRUST_get_trust := LoadLibCryptoFunction('X509_TRUST_get_trust');
  FuncLoadError := not assigned(X509_TRUST_get_trust);
  if FuncLoadError then
  begin
    X509_TRUST_get_trust :=  @ERROR_X509_TRUST_get_trust;
  end;

  X509_NAME_hash_ex := LoadLibCryptoFunction('X509_NAME_hash_ex');
  FuncLoadError := not assigned(X509_NAME_hash_ex);
  if FuncLoadError then
  begin
    X509_NAME_hash_ex :=  @ERROR_X509_NAME_hash_ex;
  end;

end;

procedure UnLoad;
begin
  X509_CRL_set_default_method := nil;
  X509_CRL_METHOD_free := nil;
  X509_CRL_set_meth_data := nil;
  X509_CRL_get_meth_data := nil;
  X509_verify_cert_error_string := nil;
  X509_verify := nil;
  X509_REQ_verify := nil;
  X509_CRL_verify := nil;
  NETSCAPE_SPKI_verify := nil;
  NETSCAPE_SPKI_b64_decode := nil;
  NETSCAPE_SPKI_b64_encode := nil;
  NETSCAPE_SPKI_get_pubkey := nil;
  NETSCAPE_SPKI_set_pubkey := nil;
  NETSCAPE_SPKI_print := nil;
  X509_signature_dump := nil;
  X509_signature_print := nil;
  X509_sign := nil;
  X509_sign_ctx := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_http_nbio := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_REQ_sign := nil;
  X509_REQ_sign_ctx := nil;
  X509_CRL_sign := nil;
  X509_CRL_sign_ctx := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_CRL_http_nbio := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  NETSCAPE_SPKI_sign := nil;
  X509_pubkey_digest := nil;
  X509_digest := nil;
  X509_CRL_digest := nil;
  X509_REQ_digest := nil;
  X509_NAME_digest := nil;
  d2i_X509_bio := nil;
  i2d_X509_bio := nil;
  d2i_X509_CRL_bio := nil;
  i2d_X509_CRL_bio := nil;
  d2i_X509_REQ_bio := nil;
  i2d_X509_REQ_bio := nil;
  d2i_RSAPrivateKey_bio := nil;
  i2d_RSAPrivateKey_bio := nil;
  d2i_RSAPublicKey_bio := nil;
  i2d_RSAPublicKey_bio := nil;
  d2i_RSA_PUBKEY_bio := nil;
  i2d_RSA_PUBKEY_bio := nil;
  d2i_DSA_PUBKEY_bio := nil;
  i2d_DSA_PUBKEY_bio := nil;
  d2i_DSAPrivateKey_bio := nil;
  i2d_DSAPrivateKey_bio := nil;
  d2i_EC_PUBKEY_bio := nil;
  i2d_EC_PUBKEY_bio := nil;
  d2i_ECPrivateKey_bio := nil;
  i2d_ECPrivateKey_bio := nil;
  d2i_PKCS8_bio := nil;
  i2d_PKCS8_bio := nil;
  d2i_PKCS8_PRIV_KEY_INFO_bio := nil;
  i2d_PKCS8_PRIV_KEY_INFO_bio := nil;
  i2d_PKCS8PrivateKeyInfo_bio := nil;
  i2d_PrivateKey_bio := nil;
  d2i_PrivateKey_bio := nil;
  i2d_PUBKEY_bio := nil;
  d2i_PUBKEY_bio := nil;
  X509_dup := nil;
  X509_ATTRIBUTE_dup := nil;
  X509_EXTENSION_dup := nil;
  X509_CRL_dup := nil;
  X509_REVOKED_dup := nil;
  X509_REQ_dup := nil;
  X509_ALGOR_dup := nil;
  X509_ALGOR_set0 := nil;
  X509_ALGOR_get0 := nil;
  X509_ALGOR_set_md := nil;
  X509_ALGOR_cmp := nil;
  X509_NAME_dup := nil;
  X509_NAME_ENTRY_dup := nil;
  X509_cmp_time := nil;
  X509_cmp_current_time := nil;
  X509_time_adj := nil;
  X509_time_adj_ex := nil;
  X509_gmtime_adj := nil;
  X509_get_default_cert_area := nil;
  X509_get_default_cert_dir := nil;
  X509_get_default_cert_file := nil;
  X509_get_default_cert_dir_env := nil;
  X509_get_default_cert_file_env := nil;
  X509_get_default_private_dir := nil;
  X509_to_X509_REQ := nil;
  X509_REQ_to_X509 := nil;
  X509_ALGOR_new := nil;
  X509_ALGOR_free := nil;
  d2i_X509_ALGOR := nil;
  i2d_X509_ALGOR := nil;
  X509_VAL_new := nil;
  X509_VAL_free := nil;
  d2i_X509_VAL := nil;
  i2d_X509_VAL := nil;
  X509_PUBKEY_new := nil;
  X509_PUBKEY_free := nil;
  d2i_X509_PUBKEY := nil;
  i2d_X509_PUBKEY := nil;
  X509_PUBKEY_set := nil;
  X509_PUBKEY_get0 := nil;
  X509_PUBKEY_get := nil;
  X509_get_pathlen := nil;
  i2d_PUBKEY := nil;
  d2i_PUBKEY := nil;
  i2d_RSA_PUBKEY := nil;
  d2i_RSA_PUBKEY := nil;
  i2d_DSA_PUBKEY := nil;
  d2i_DSA_PUBKEY := nil;
  i2d_EC_PUBKEY := nil;
  d2i_EC_PUBKEY := nil;
  X509_SIG_new := nil;
  X509_SIG_free := nil;
  d2i_X509_SIG := nil;
  i2d_X509_SIG := nil;
  X509_SIG_get0 := nil;
  X509_SIG_getm := nil;
  X509_REQ_INFO_new := nil;
  X509_REQ_INFO_free := nil;
  d2i_X509_REQ_INFO := nil;
  i2d_X509_REQ_INFO := nil;
  X509_REQ_new := nil;
  X509_REQ_free := nil;
  d2i_X509_REQ := nil;
  i2d_X509_REQ := nil;
  X509_ATTRIBUTE_new := nil;
  X509_ATTRIBUTE_free := nil;
  d2i_X509_ATTRIBUTE := nil;
  i2d_X509_ATTRIBUTE := nil;
  X509_ATTRIBUTE_create := nil;
  X509_EXTENSION_new := nil;
  X509_EXTENSION_free := nil;
  d2i_X509_EXTENSION := nil;
  i2d_X509_EXTENSION := nil;
  X509_NAME_ENTRY_new := nil;
  X509_NAME_ENTRY_free := nil;
  d2i_X509_NAME_ENTRY := nil;
  i2d_X509_NAME_ENTRY := nil;
  X509_NAME_new := nil;
  X509_NAME_free := nil;
  d2i_X509_NAME := nil;
  i2d_X509_NAME := nil;
  X509_NAME_set := nil;
  X509_new := nil;
  X509_free := nil;
  d2i_X509 := nil;
  i2d_X509 := nil;
  X509_set_ex_data := nil;
  X509_get_ex_data := nil;
  i2d_X509_AUX := nil;
  d2i_X509_AUX := nil;
  i2d_re_X509_tbs := nil;
  X509_SIG_INFO_get := nil;
  X509_SIG_INFO_set := nil;
  X509_get_signature_info := nil;
  X509_get0_signature := nil;
  X509_get_signature_nid := nil;
  X509_trusted := nil;
  X509_alias_set1 := nil;
  X509_keyid_set1 := nil;
  X509_alias_get0 := nil;
  X509_keyid_get0 := nil;
  X509_TRUST_set := nil;
  X509_add1_trust_object := nil;
  X509_add1_reject_object := nil;
  X509_trust_clear := nil;
  X509_reject_clear := nil;
  X509_REVOKED_new := nil;
  X509_REVOKED_free := nil;
  d2i_X509_REVOKED := nil;
  i2d_X509_REVOKED := nil;
  X509_CRL_INFO_new := nil;
  X509_CRL_INFO_free := nil;
  d2i_X509_CRL_INFO := nil;
  i2d_X509_CRL_INFO := nil;
  X509_CRL_new := nil;
  X509_CRL_free := nil;
  d2i_X509_CRL := nil;
  i2d_X509_CRL := nil;
  X509_CRL_add0_revoked := nil;
  X509_CRL_get0_by_serial := nil;
  X509_CRL_get0_by_cert := nil;
  X509_PKEY_new := nil;
  X509_PKEY_free := nil;
  X509_INFO_new := nil;
  X509_INFO_free := nil;
  X509_NAME_oneline := nil;
  ASN1_item_digest := nil;
  ASN1_item_verify := nil;
  ASN1_item_sign := nil;
  ASN1_item_sign_ctx := nil;
  X509_get_version := nil;
  X509_set_version := nil;
  X509_set_serialNumber := nil;
  X509_get_serialNumber := nil;
  X509_get0_serialNumber := nil;
  X509_set_issuer_name := nil;
  X509_get_issuer_name := nil;
  X509_set_subject_name := nil;
  X509_get_subject_name := nil;
  X509_get0_notBefore := nil;
  X509_getm_notBefore := nil;
  X509_set1_notBefore := nil;
  X509_get0_notAfter := nil;
  X509_getm_notAfter := nil;
  X509_set1_notAfter := nil;
  X509_set_pubkey := nil;
  X509_up_ref := nil;
  X509_get_signature_type := nil;
  X509_get_X509_PUBKEY := nil;
  X509_get0_uids := nil;
  X509_get0_tbs_sigalg := nil;
  X509_get0_pubkey := nil;
  X509_get_pubkey := nil;
  X509_get0_pubkey_bitstr := nil;
  X509_certificate_type := nil;
  X509_REQ_get_version := nil;
  X509_REQ_set_version := nil;
  X509_REQ_get_subject_name := nil;
  X509_REQ_set_subject_name := nil;
  X509_REQ_get0_signature := nil;
  X509_REQ_get_signature_nid := nil;
  i2d_re_X509_REQ_tbs := nil;
  X509_REQ_set_pubkey := nil;
  X509_REQ_get_pubkey := nil;
  X509_REQ_get0_pubkey := nil;
  X509_REQ_get_X509_PUBKEY := nil;
  X509_REQ_extension_nid := nil;
  X509_REQ_get_extension_nids := nil;
  X509_REQ_set_extension_nids := nil;
  X509_REQ_get_attr_count := nil;
  X509_REQ_get_attr_by_NID := nil;
  X509_REQ_get_attr_by_OBJ := nil;
  X509_REQ_get_attr := nil;
  X509_REQ_delete_attr := nil;
  X509_REQ_add1_attr := nil;
  X509_REQ_add1_attr_by_OBJ := nil;
  X509_REQ_add1_attr_by_NID := nil;
  X509_REQ_add1_attr_by_txt := nil;
  X509_CRL_set_version := nil;
  X509_CRL_set_issuer_name := nil;
  X509_CRL_set1_lastUpdate := nil;
  X509_CRL_set1_nextUpdate := nil;
  X509_CRL_sort := nil;
  X509_CRL_up_ref := nil;
  X509_CRL_get_version := nil;
  X509_CRL_get0_lastUpdate := nil;
  X509_CRL_get0_nextUpdate := nil;
  X509_CRL_get_issuer := nil;
  X509_CRL_get0_signature := nil;
  X509_CRL_get_signature_nid := nil;
  i2d_re_X509_CRL_tbs := nil;
  X509_REVOKED_get0_serialNumber := nil;
  X509_REVOKED_set_serialNumber := nil;
  X509_REVOKED_get0_revocationDate := nil;
  X509_REVOKED_set_revocationDate := nil;
  X509_CRL_diff := nil;
  X509_REQ_check_private_key := nil;
  X509_check_private_key := nil;
  X509_CRL_check_suiteb := nil;
  X509_issuer_and_serial_cmp := nil;
  X509_issuer_and_serial_hash := nil;
  X509_issuer_name_cmp := nil;
  X509_issuer_name_hash := nil;
  X509_subject_name_cmp := nil;
  X509_subject_name_hash := nil;
  X509_cmp := nil;
  X509_NAME_cmp := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_NAME_hash := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_NAME_hash_old := nil;
  X509_CRL_cmp := nil;
  X509_CRL_match := nil;
  X509_aux_print := nil;
  X509_NAME_print := nil;
  X509_NAME_print_ex := nil;
  X509_print_ex := nil;
  X509_print := nil;
  X509_ocspid_print := nil;
  X509_CRL_print_ex := nil;
  X509_CRL_print := nil;
  X509_REQ_print_ex := nil;
  X509_REQ_print := nil;
  X509_NAME_entry_count := nil;
  X509_NAME_get_text_by_NID := nil;
  X509_NAME_get_text_by_OBJ := nil;
  X509_NAME_get_index_by_NID := nil;
  X509_NAME_get_index_by_OBJ := nil;
  X509_NAME_get_entry := nil;
  X509_NAME_delete_entry := nil;
  X509_NAME_add_entry := nil;
  X509_NAME_add_entry_by_OBJ := nil;
  X509_NAME_add_entry_by_NID := nil;
  X509_NAME_ENTRY_create_by_txt := nil;
  X509_NAME_ENTRY_create_by_NID := nil;
  X509_NAME_add_entry_by_txt := nil;
  X509_NAME_ENTRY_create_by_OBJ := nil;
  X509_NAME_ENTRY_set_object := nil;
  X509_NAME_ENTRY_set_data := nil;
  X509_NAME_ENTRY_get_object := nil;
  X509_NAME_ENTRY_get_data := nil;
  X509_NAME_ENTRY_set := nil;
  X509_NAME_get0_der := nil;
  X509_get_ext_count := nil;
  X509_get_ext_by_NID := nil;
  X509_get_ext_by_OBJ := nil;
  X509_get_ext_by_critical := nil;
  X509_get_ext := nil;
  X509_delete_ext := nil;
  X509_add_ext := nil;
  X509_get_ext_d2i := nil;
  X509_add1_ext_i2d := nil;
  X509_CRL_get_ext_count := nil;
  X509_CRL_get_ext_by_NID := nil;
  X509_CRL_get_ext_by_OBJ := nil;
  X509_CRL_get_ext_by_critical := nil;
  X509_CRL_get_ext := nil;
  X509_CRL_delete_ext := nil;
  X509_CRL_add_ext := nil;
  X509_CRL_get_ext_d2i := nil;
  X509_CRL_add1_ext_i2d := nil;
  X509_REVOKED_get_ext_count := nil;
  X509_REVOKED_get_ext_by_NID := nil;
  X509_REVOKED_get_ext_by_OBJ := nil;
  X509_REVOKED_get_ext_by_critical := nil;
  X509_REVOKED_get_ext := nil;
  X509_REVOKED_delete_ext := nil;
  X509_REVOKED_add_ext := nil;
  X509_REVOKED_get_ext_d2i := nil;
  X509_REVOKED_add1_ext_i2d := nil;
  X509_EXTENSION_create_by_NID := nil;
  X509_EXTENSION_create_by_OBJ := nil;
  X509_EXTENSION_set_object := nil;
  X509_EXTENSION_set_critical := nil;
  X509_EXTENSION_set_data := nil;
  X509_EXTENSION_get_object := nil;
  X509_EXTENSION_get_data := nil;
  X509_EXTENSION_get_critical := nil;
  X509_ATTRIBUTE_create_by_NID := nil;
  X509_ATTRIBUTE_create_by_OBJ := nil;
  X509_ATTRIBUTE_create_by_txt := nil;
  X509_ATTRIBUTE_set1_object := nil;
  X509_ATTRIBUTE_set1_data := nil;
  X509_ATTRIBUTE_get0_data := nil;
  X509_ATTRIBUTE_count := nil;
  X509_ATTRIBUTE_get0_object := nil;
  X509_ATTRIBUTE_get0_type := nil;
  EVP_PKEY_get_attr_count := nil;
  EVP_PKEY_get_attr_by_NID := nil;
  EVP_PKEY_get_attr_by_OBJ := nil;
  EVP_PKEY_get_attr := nil;
  EVP_PKEY_delete_attr := nil;
  EVP_PKEY_add1_attr := nil;
  EVP_PKEY_add1_attr_by_OBJ := nil;
  EVP_PKEY_add1_attr_by_NID := nil;
  EVP_PKEY_add1_attr_by_txt := nil;
  X509_verify_cert := nil;
  PKCS5_pbe_set0_algor := nil;
  PKCS5_pbe_set := nil;
  PKCS5_pbe2_set := nil;
  PKCS5_pbe2_set_iv := nil;
  PKCS5_pbe2_set_scrypt := nil;
  PKCS5_pbkdf2_set := nil;
  EVP_PKCS82PKEY := nil;
  EVP_PKEY2PKCS8 := nil;
  PKCS8_pkey_set0 := nil;
  PKCS8_pkey_get0 := nil;
  PKCS8_pkey_add1_attr_by_NID := nil;
  X509_PUBKEY_set0_param := nil;
  X509_PUBKEY_get0_param := nil;
  X509_check_trust := nil;
  X509_TRUST_get_count := nil;
  X509_TRUST_get0 := nil;
  X509_TRUST_get_by_id := nil;
  X509_TRUST_cleanup := nil;
  X509_TRUST_get_flags := nil;
  X509_TRUST_get0_name := nil;
  X509_TRUST_get_trust := nil;
  X509_NAME_hash_ex := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
