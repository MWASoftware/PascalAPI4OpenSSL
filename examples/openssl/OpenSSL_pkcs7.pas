(* This unit was generated from the source file pkcs7.h2pas 
It should not be modified directly. All changes should be made to pkcs7.h2pas
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


unit OpenSSL_pkcs7;


interface

// Headers for OpenSSL 1.1.1
// pkcs7.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ;

// the following emits are a workaround to a
// name conflict with Win32 API header files
{$IFDEF WINDOWS}
(*$HPPEMIT '#undef PKCS7_ISSUER_AND_SERIAL'*)
(*$HPPEMIT '#undef PKCS7_SIGNER_INFO'*)
{$ENDIF}

const
  PKCS7_S_HEADER = 0;
  PKCS7_S_BODY   = 1;
  PKCS7_S_TAIL   = 2;

  PKCS7_OP_SET_DETACHED_SIGNATURE = 1;
  PKCS7_OP_GET_DETACHED_SIGNATURE = 2;

  (* S/MIME related flags *)
  PKCS7_TEXT            =     $1;
  PKCS7_NOCERTS         =     $2;
  PKCS7_NOSIGS          =     $4;
  PKCS7_NOCHAIN         =     $8;
  PKCS7_NOINTERN        =    $10;
  PKCS7_NOVERIFY        =    $20;
  PKCS7_DETACHED        =    $40;
  PKCS7_BINARY          =    $80;
  PKCS7_NOATTR          =   $100;
  PKCS7_NOSMIMECAP      =   $200;
  PKCS7_NOOLDMIMETYPE   =   $400;
  PKCS7_CRLFEOL         =   $800;
  // Added '_CONST' to avoid name clashes
  PKCS7_STREAM_CONST    =  $1000;
  PKCS7_NOCRL           =  $2000;
  PKCS7_PARTIAL         =  $4000;
  PKCS7_REUSE_DIGEST    =  $8000;
  PKCS7_NO_DUAL_CONTENT = $10000;

  (* Flags: for compatibility with older code *)
  SMIME_TEXT      = PKCS7_TEXT;
  SMIME_NOCERTS   = PKCS7_NOCERTS;
  SMIME_NOSIGS    = PKCS7_NOSIGS;
  SMIME_NOCHAIN   = PKCS7_NOCHAIN;
  SMIME_NOINTERN  = PKCS7_NOINTERN;
  SMIME_NOVERIFY  = PKCS7_NOVERIFY;
  SMIME_DETACHED  = PKCS7_DETACHED;
  SMIME_BINARY    = PKCS7_BINARY;
  SMIME_NOATTR    = PKCS7_NOATTR;

  (* CRLF ASCII canonicalisation *)
  SMIME_ASCIICRLF = $80000;

type
  PPKCS7 = ^PKCS7;
  PPPKCS7 = ^PPKCS7;

  PPKCS7_DIGEST = ^PKCS7_DIGEST;
  PPPKCS7_DIGEST = ^PPKCS7_DIGEST;

  pkcs7_issuer_and_serial_st = record
    issue: PX509_NAME;
    serial: PASN1_INTEGER;
  end;
  PKCS7_ISSUER_AND_SERIAL = pkcs7_issuer_and_serial_st;
  PPKCS7_ISSUER_AND_SERIAL = ^PKCS7_ISSUER_AND_SERIAL;
  PPPKCS7_ISSUER_AND_SERIAL = ^PPKCS7_ISSUER_AND_SERIAL;

  pkcs7_signer_info_st = record
    version: PASN1_INTEGER;
    issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
    digest_alg: PX509_ALGOR;
    auth_attr: Pointer; //PSTACK_OF_X509_ATTRIBUTE;
    digest_enc_alg: PX509_ALGOR;
    enc_digest: PASN1_OCTET_STRING;
    unauth_attr: Pointer; //PSTACK_OF_X509_ATTRIBUTE;
    pkey: PEVP_PKEY;
  end;
  PKCS7_SIGNER_INFO = pkcs7_issuer_and_serial_st;
  PPKCS7_SIGNER_INFO = ^PKCS7_SIGNER_INFO;
  PPPKCS7_SIGNER_INFO = ^PPKCS7_SIGNER_INFO;

  pkcs7_recip_info_st = record
    version: PASN1_INTEGER;
    issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
    key_enc_algor: PX509_ALGOR;
    enc_key: PASN1_OCTET_STRING;
    cert: PX509;
  end;
  PKCS7_RECIP_INFO = pkcs7_recip_info_st;
  PPKCS7_RECIP_INFO = ^PKCS7_RECIP_INFO;
  PPPKCS7_RECIP_INFO = ^PPKCS7_RECIP_INFO;

  pkcs7_signed_st = record
    version: PASN1_INTEGER;
    md_algs: Pointer; //PSTACK_OF_X509_ALGOR;
    cert: Pointer; //PSTACK_OF_X509;
    crl: Pointer; //PSTACK_OF_X509_CRL;
    signer_info: Pointer; //PSTACK_OF_PKCS7_SIGNER_INFO;
    contents: PPKCS7;
  end;
  PKCS7_SIGNED = pkcs7_signed_st;
  PPKCS7_SIGNED = ^PKCS7_SIGNED;
  PPPKCS7_SIGNED = ^PPKCS7_SIGNED;

  pkcs7_enc_content_st = record
    content_type: PASN1_OBJECT;
    algorithm: PX509_ALGOR;
    enc_data: PASN1_OCTET_STRING;
    cipher: PEVP_CIPHER;
  end;
  PKCS7_ENC_CONTENT = pkcs7_enc_content_st;
  PPKCS7_ENC_CONTENT = ^PKCS7_ENC_CONTENT;
  PPPKCS7_ENC_CONTENT = ^PPKCS7_ENC_CONTENT;

  pkcs7_enveloped_st = record
    version: PASN1_INTEGER;
    recipientinfo: Pointer; //PSTACK_OF_PKCS7_RECIP_INFO;
    enc_data: PPKCS7_ENC_CONTENT;
  end;
  PKCS7_ENVELOPE = pkcs7_enveloped_st;
  PPKCS7_ENVELOPE = ^PKCS7_ENVELOPE;
  PPPKCS7_ENVELOPE = ^PPKCS7_ENVELOPE;

  pkcs7_signedandenveloped_st = record
    version: PASN1_INTEGER;
    md_algs: Pointer; //PSTACK_OF_X509_ALGOR;
    cert: Pointer; //PSTACK_OF_X509;
    crl: Pointer; //PSTACK_OF_X509_CRL;
    signer_info: Pointer; //PSTACK_OF_PKCS7_SIGNER_INFO;
    enc_data: PPKCS7_ENC_CONTENT;
    recipientinfo: Pointer; //PSTACK_OF_PKCS7_RECIP_INFO;
  end;
  PKCS7_SIGN_ENVELOPE = pkcs7_signedandenveloped_st;
  PPKCS7_SIGN_ENVELOPE = ^PKCS7_SIGN_ENVELOPE;
  PPPKCS7_SIGN_ENVELOPE = ^PPKCS7_SIGN_ENVELOPE;

  pkcs7_encrypted_st = record
    version: PASN1_INTEGER;
    enc_data: PPKCS7_ENC_CONTENT;
  end;
  // Added '_STRUCT' to avoid name clashes
  PKCS7_ENCRYPT_STRUCT = pkcs7_encrypted_st;
  PPKCS7_ENCRYPT_STRUCT = ^PKCS7_ENCRYPT_STRUCT;
  PPPKCS7_ENCRYPT_STRUCT = ^PPKCS7_ENCRYPT_STRUCT;

  pkcs7_st_d = record
    case Integer of
    0: (ptr: PAnsiChar);
    1: (data: PASN1_OCTET_STRING);
    2: (sign: PPKCS7_SIGNED);
    3: (enveloped: PPKCS7_ENVELOPE);
    4: (signed_and_enveloped: PPKCS7_SIGN_ENVELOPE);
    5: (digest: PPKCS7_DIGEST);
    6: (encrypted: PPKCS7_ENCRYPT_STRUCT);
    7: (other: PASN1_TYPE);
  end;
  pkcs7_st = record
    asn1: PByte;
    length: TOpenSSL_C_LONG;
    state: TOpenSSL_C_INT;
    detached: TOpenSSL_C_INT;
    type_: PASN1_OBJECT;
    d: pkcs7_st_d;
  end;
  PKCS7 = pkcs7_st;

  pkcs7_digest_st = record
    version: PASN1_INTEGER;
    md: PX509_ALGOR;
    contents: PPKCS7;
    digest: PASN1_OCTET_STRING;
  end;
  PKCS7_DIGEST = pkcs7_digest_st;

  //function PKCS7_ISSUER_AND_SERIAL_new: PPKCS7_ISSUER_AND_SERIAL;
  //procedure PKCS7_ISSUER_AND_SERIAL_free(a: PPKCS7_ISSUER_AND_SERIAL);
  //function d2i_PKCS7_ISSUER_AND_SERIAL(a: PPPKCS7_ISSUER_AND_SERIAL; const in_: PByte; len: TOpenSSL_C_LONG): PPKCS7_ISSUER_AND_SERIAL;
  //function i2d_PKCS7_ISSUER_AND_SERIAL(const a: PPKCS7_ISSUER_AND_SERIAL; out_: PByte): TOpenSSL_C_INT;
  //function PKCS7_ISSUER_AND_SERIAL_it: PASN1_ITEM;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM PKCS7_ISSUER_AND_SERIAL_digest}
{$EXTERNALSYM PKCS7_dup}
{$EXTERNALSYM d2i_PKCS7_bio}
{$EXTERNALSYM i2d_PKCS7_bio}
{$EXTERNALSYM i2d_PKCS7_bio_stream}
{$EXTERNALSYM PEM_write_bio_PKCS7_stream}
{$EXTERNALSYM PKCS7_ctrl}
{$EXTERNALSYM PKCS7_set_type}
{$EXTERNALSYM PKCS7_set0_type_other}
{$EXTERNALSYM PKCS7_set_content}
{$EXTERNALSYM PKCS7_SIGNER_INFO_set}
{$EXTERNALSYM PKCS7_SIGNER_INFO_sign}
{$EXTERNALSYM PKCS7_add_signer}
{$EXTERNALSYM PKCS7_add_certificate}
{$EXTERNALSYM PKCS7_add_crl}
{$EXTERNALSYM PKCS7_content_new}
{$EXTERNALSYM PKCS7_dataVerify}
{$EXTERNALSYM PKCS7_signatureVerify}
{$EXTERNALSYM PKCS7_dataInit}
{$EXTERNALSYM PKCS7_dataFinal}
{$EXTERNALSYM PKCS7_dataDecode}
{$EXTERNALSYM PKCS7_add_signature}
{$EXTERNALSYM PKCS7_cert_from_signer_info}
{$EXTERNALSYM PKCS7_set_digest}
{$EXTERNALSYM PKCS7_add_recipient}
{$EXTERNALSYM PKCS7_SIGNER_INFO_get0_algs}
{$EXTERNALSYM PKCS7_RECIP_INFO_get0_alg}
{$EXTERNALSYM PKCS7_add_recipient_info}
{$EXTERNALSYM PKCS7_RECIP_INFO_set}
{$EXTERNALSYM PKCS7_set_cipher}
{$EXTERNALSYM PKCS7_stream}
{$EXTERNALSYM PKCS7_get_issuer_and_serial}
{$EXTERNALSYM PKCS7_add_signed_attribute}
{$EXTERNALSYM PKCS7_add_attribute}
{$EXTERNALSYM PKCS7_get_attribute}
{$EXTERNALSYM PKCS7_get_signed_attribute}
{$EXTERNALSYM PKCS7_sign_add_signer}
{$EXTERNALSYM PKCS7_final}
{$EXTERNALSYM PKCS7_decrypt}
{$EXTERNALSYM PKCS7_add_attrib_content_type}
{$EXTERNALSYM PKCS7_add0_attrib_signing_time}
{$EXTERNALSYM PKCS7_add1_attrib_digest}
{$EXTERNALSYM SMIME_write_PKCS7}
{$EXTERNALSYM SMIME_read_PKCS7}
{$EXTERNALSYM BIO_new_PKCS7}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function PKCS7_ISSUER_AND_SERIAL_digest(data: PPKCS7_ISSUER_AND_SERIAL; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_dup(p7: PPKCS7): PPKCS7; cdecl; external CLibCrypto;
function d2i_PKCS7_bio(bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl; external CLibCrypto;
function i2d_PKCS7_bio(bp: PBIO; p7: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PKCS7_bio_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS7_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_ctrl(p7: PPKCS7; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: PAnsiChar): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function PKCS7_set_type(p7: PPKCS7; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_set0_type_other(p7: PPKCS7; typepkcs7_signer_info_: TOpenSSL_C_INT; other: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_set_content(p7: PPKCS7; p7_data: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_SIGNER_INFO_set(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_SIGNER_INFO_sign(si: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add_signer(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add_certificate(p7: PPKCS7; x509: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add_crl(p7: PPKCS7; x509: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_content_new(p7: PPKCS7; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_dataVerify(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_signatureVerify(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; x509: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_dataInit(p7: PPKCS7; bio: PBIO): PBIO; cdecl; external CLibCrypto;
function PKCS7_dataFinal(p7: PPKCS7; bio: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_dataDecode(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl; external CLibCrypto;
function PKCS7_add_signature(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl; external CLibCrypto;
function PKCS7_cert_from_signer_info(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl; external CLibCrypto;
function PKCS7_set_digest(p7: PPKCS7; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add_recipient(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl; external CLibCrypto;
procedure PKCS7_SIGNER_INFO_get0_algs(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl; external CLibCrypto;
procedure PKCS7_RECIP_INFO_get0_alg(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl; external CLibCrypto;
function PKCS7_add_recipient_info(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_RECIP_INFO_set(p7i: PPKCS7_RECIP_INFO; x509: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_set_cipher(p7: PPKCS7; const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_stream(boundary: PPPByte; p7: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_get_issuer_and_serial(p7: PPKCS7; idx: TOpenSSL_C_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl; external CLibCrypto;
function PKCS7_add_signed_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; value: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_get_attribute(si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl; external CLibCrypto;
function PKCS7_get_signed_attribute(si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl; external CLibCrypto;
function PKCS7_sign_add_signer(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_INT): PPKCS7_SIGNER_INFO; cdecl; external CLibCrypto;
function PKCS7_final(p7: PPKCS7; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_decrypt(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add_attrib_content_type(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add0_attrib_signing_time(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS7_add1_attrib_digest(si: PPKCS7_SIGNER_INFO; const md: PByte; mdlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_write_PKCS7(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_read_PKCS7(bio: PBIO; bcont: PPBIO): PPKCS7; cdecl; external CLibCrypto;
function BIO_new_PKCS7(out_: PBIO; p7: PPKCS7): PBIO; cdecl; external CLibCrypto;

{$ELSE}
var
  PKCS7_ISSUER_AND_SERIAL_digest: function (data: PPKCS7_ISSUER_AND_SERIAL; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_dup: function (p7: PPKCS7): PPKCS7; cdecl = nil;
  d2i_PKCS7_bio: function (bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl = nil;
  i2d_PKCS7_bio: function (bp: PBIO; p7: PPKCS7): TOpenSSL_C_INT; cdecl = nil;
  i2d_PKCS7_bio_stream: function (out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_PKCS7_stream: function (out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_ctrl: function (p7: PPKCS7; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: PAnsiChar): TOpenSSL_C_LONG; cdecl = nil;
  PKCS7_set_type: function (p7: PPKCS7; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_set0_type_other: function (p7: PPKCS7; typepkcs7_signer_info_: TOpenSSL_C_INT; other: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_set_content: function (p7: PPKCS7; p7_data: PPKCS7): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_SIGNER_INFO_set: function (p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_SIGNER_INFO_sign: function (si: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add_signer: function (p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add_certificate: function (p7: PPKCS7; x509: PX509): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add_crl: function (p7: PPKCS7; x509: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_content_new: function (p7: PPKCS7; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_dataVerify: function (cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_signatureVerify: function (bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; x509: PX509): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_dataInit: function (p7: PPKCS7; bio: PBIO): PBIO; cdecl = nil;
  PKCS7_dataFinal: function (p7: PPKCS7; bio: PBIO): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_dataDecode: function (p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl = nil;
  PKCS7_add_signature: function (p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl = nil;
  PKCS7_cert_from_signer_info: function (p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl = nil;
  PKCS7_set_digest: function (p7: PPKCS7; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add_recipient: function (p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl = nil;
  PKCS7_SIGNER_INFO_get0_algs: procedure (si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl = nil;
  PKCS7_RECIP_INFO_get0_alg: procedure (ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl = nil;
  PKCS7_add_recipient_info: function (p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_RECIP_INFO_set: function (p7i: PPKCS7_RECIP_INFO; x509: PX509): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_set_cipher: function (p7: PPKCS7; const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_stream: function (boundary: PPPByte; p7: PPKCS7): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_get_issuer_and_serial: function (p7: PPKCS7; idx: TOpenSSL_C_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl = nil;
  PKCS7_add_signed_attribute: function (p7si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add_attribute: function (p7si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; value: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_get_attribute: function (si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl = nil;
  PKCS7_get_signed_attribute: function (si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl = nil;
  PKCS7_sign_add_signer: function (p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_INT): PPKCS7_SIGNER_INFO; cdecl = nil;
  PKCS7_final: function (p7: PPKCS7; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_decrypt: function (p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add_attrib_content_type: function (si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add0_attrib_signing_time: function (si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  PKCS7_add1_attrib_digest: function (si: PPKCS7_SIGNER_INFO; const md: PByte; mdlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SMIME_write_PKCS7: function (bio: PBIO; p7: PPKCS7; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SMIME_read_PKCS7: function (bio: PBIO; bcont: PPBIO): PPKCS7; cdecl = nil;
  BIO_new_PKCS7: function (out_: PBIO; p7: PPKCS7): PBIO; cdecl = nil;
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
function ERROR_PKCS7_ISSUER_AND_SERIAL_digest(data: PPKCS7_ISSUER_AND_SERIAL; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_ISSUER_AND_SERIAL_digest');
end;

function ERROR_PKCS7_dup(p7: PPKCS7): PPKCS7; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_dup');
end;

function ERROR_d2i_PKCS7_bio(bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS7_bio');
end;

function ERROR_i2d_PKCS7_bio(bp: PBIO; p7: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS7_bio');
end;

function ERROR_i2d_PKCS7_bio_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS7_bio_stream');
end;

function ERROR_PEM_write_bio_PKCS7_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS7_stream');
end;

function ERROR_PKCS7_ctrl(p7: PPKCS7; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: PAnsiChar): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_ctrl');
end;

function ERROR_PKCS7_set_type(p7: PPKCS7; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_set_type');
end;

function ERROR_PKCS7_set0_type_other(p7: PPKCS7; typepkcs7_signer_info_: TOpenSSL_C_INT; other: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_set0_type_other');
end;

function ERROR_PKCS7_set_content(p7: PPKCS7; p7_data: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_set_content');
end;

function ERROR_PKCS7_SIGNER_INFO_set(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_SIGNER_INFO_set');
end;

function ERROR_PKCS7_SIGNER_INFO_sign(si: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_SIGNER_INFO_sign');
end;

function ERROR_PKCS7_add_signer(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_signer');
end;

function ERROR_PKCS7_add_certificate(p7: PPKCS7; x509: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_certificate');
end;

function ERROR_PKCS7_add_crl(p7: PPKCS7; x509: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_crl');
end;

function ERROR_PKCS7_content_new(p7: PPKCS7; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_content_new');
end;

function ERROR_PKCS7_dataVerify(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_dataVerify');
end;

function ERROR_PKCS7_signatureVerify(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; x509: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_signatureVerify');
end;

function ERROR_PKCS7_dataInit(p7: PPKCS7; bio: PBIO): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_dataInit');
end;

function ERROR_PKCS7_dataFinal(p7: PPKCS7; bio: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_dataFinal');
end;

function ERROR_PKCS7_dataDecode(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_dataDecode');
end;

function ERROR_PKCS7_add_signature(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_signature');
end;

function ERROR_PKCS7_cert_from_signer_info(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_cert_from_signer_info');
end;

function ERROR_PKCS7_set_digest(p7: PPKCS7; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_set_digest');
end;

function ERROR_PKCS7_add_recipient(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_recipient');
end;

procedure ERROR_PKCS7_SIGNER_INFO_get0_algs(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_SIGNER_INFO_get0_algs');
end;

procedure ERROR_PKCS7_RECIP_INFO_get0_alg(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_RECIP_INFO_get0_alg');
end;

function ERROR_PKCS7_add_recipient_info(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_recipient_info');
end;

function ERROR_PKCS7_RECIP_INFO_set(p7i: PPKCS7_RECIP_INFO; x509: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_RECIP_INFO_set');
end;

function ERROR_PKCS7_set_cipher(p7: PPKCS7; const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_set_cipher');
end;

function ERROR_PKCS7_stream(boundary: PPPByte; p7: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_stream');
end;

function ERROR_PKCS7_get_issuer_and_serial(p7: PPKCS7; idx: TOpenSSL_C_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_get_issuer_and_serial');
end;

function ERROR_PKCS7_add_signed_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_signed_attribute');
end;

function ERROR_PKCS7_add_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; value: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_attribute');
end;

function ERROR_PKCS7_get_attribute(si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_get_attribute');
end;

function ERROR_PKCS7_get_signed_attribute(si: PPKCS7_SIGNER_INFO; nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_get_signed_attribute');
end;

function ERROR_PKCS7_sign_add_signer(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_INT): PPKCS7_SIGNER_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_sign_add_signer');
end;

function ERROR_PKCS7_final(p7: PPKCS7; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_final');
end;

function ERROR_PKCS7_decrypt(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_decrypt');
end;

function ERROR_PKCS7_add_attrib_content_type(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add_attrib_content_type');
end;

function ERROR_PKCS7_add0_attrib_signing_time(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add0_attrib_signing_time');
end;

function ERROR_PKCS7_add1_attrib_digest(si: PPKCS7_SIGNER_INFO; const md: PByte; mdlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_add1_attrib_digest');
end;

function ERROR_SMIME_write_PKCS7(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_write_PKCS7');
end;

function ERROR_SMIME_read_PKCS7(bio: PBIO; bcont: PPBIO): PPKCS7; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_read_PKCS7');
end;

function ERROR_BIO_new_PKCS7(out_: PBIO; p7: PPKCS7): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_PKCS7');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  PKCS7_ISSUER_AND_SERIAL_digest := LoadLibCryptoFunction('PKCS7_ISSUER_AND_SERIAL_digest');
  FuncLoadError := not assigned(PKCS7_ISSUER_AND_SERIAL_digest);
  if FuncLoadError then
  begin
    PKCS7_ISSUER_AND_SERIAL_digest :=  @ERROR_PKCS7_ISSUER_AND_SERIAL_digest;
  end;

  PKCS7_dup := LoadLibCryptoFunction('PKCS7_dup');
  FuncLoadError := not assigned(PKCS7_dup);
  if FuncLoadError then
  begin
    PKCS7_dup :=  @ERROR_PKCS7_dup;
  end;

  d2i_PKCS7_bio := LoadLibCryptoFunction('d2i_PKCS7_bio');
  FuncLoadError := not assigned(d2i_PKCS7_bio);
  if FuncLoadError then
  begin
    d2i_PKCS7_bio :=  @ERROR_d2i_PKCS7_bio;
  end;

  i2d_PKCS7_bio := LoadLibCryptoFunction('i2d_PKCS7_bio');
  FuncLoadError := not assigned(i2d_PKCS7_bio);
  if FuncLoadError then
  begin
    i2d_PKCS7_bio :=  @ERROR_i2d_PKCS7_bio;
  end;

  i2d_PKCS7_bio_stream := LoadLibCryptoFunction('i2d_PKCS7_bio_stream');
  FuncLoadError := not assigned(i2d_PKCS7_bio_stream);
  if FuncLoadError then
  begin
    i2d_PKCS7_bio_stream :=  @ERROR_i2d_PKCS7_bio_stream;
  end;

  PEM_write_bio_PKCS7_stream := LoadLibCryptoFunction('PEM_write_bio_PKCS7_stream');
  FuncLoadError := not assigned(PEM_write_bio_PKCS7_stream);
  if FuncLoadError then
  begin
    PEM_write_bio_PKCS7_stream :=  @ERROR_PEM_write_bio_PKCS7_stream;
  end;

  PKCS7_ctrl := LoadLibCryptoFunction('PKCS7_ctrl');
  FuncLoadError := not assigned(PKCS7_ctrl);
  if FuncLoadError then
  begin
    PKCS7_ctrl :=  @ERROR_PKCS7_ctrl;
  end;

  PKCS7_set_type := LoadLibCryptoFunction('PKCS7_set_type');
  FuncLoadError := not assigned(PKCS7_set_type);
  if FuncLoadError then
  begin
    PKCS7_set_type :=  @ERROR_PKCS7_set_type;
  end;

  PKCS7_set0_type_other := LoadLibCryptoFunction('PKCS7_set0_type_other');
  FuncLoadError := not assigned(PKCS7_set0_type_other);
  if FuncLoadError then
  begin
    PKCS7_set0_type_other :=  @ERROR_PKCS7_set0_type_other;
  end;

  PKCS7_set_content := LoadLibCryptoFunction('PKCS7_set_content');
  FuncLoadError := not assigned(PKCS7_set_content);
  if FuncLoadError then
  begin
    PKCS7_set_content :=  @ERROR_PKCS7_set_content;
  end;

  PKCS7_SIGNER_INFO_set := LoadLibCryptoFunction('PKCS7_SIGNER_INFO_set');
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_set);
  if FuncLoadError then
  begin
    PKCS7_SIGNER_INFO_set :=  @ERROR_PKCS7_SIGNER_INFO_set;
  end;

  PKCS7_SIGNER_INFO_sign := LoadLibCryptoFunction('PKCS7_SIGNER_INFO_sign');
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_sign);
  if FuncLoadError then
  begin
    PKCS7_SIGNER_INFO_sign :=  @ERROR_PKCS7_SIGNER_INFO_sign;
  end;

  PKCS7_add_signer := LoadLibCryptoFunction('PKCS7_add_signer');
  FuncLoadError := not assigned(PKCS7_add_signer);
  if FuncLoadError then
  begin
    PKCS7_add_signer :=  @ERROR_PKCS7_add_signer;
  end;

  PKCS7_add_certificate := LoadLibCryptoFunction('PKCS7_add_certificate');
  FuncLoadError := not assigned(PKCS7_add_certificate);
  if FuncLoadError then
  begin
    PKCS7_add_certificate :=  @ERROR_PKCS7_add_certificate;
  end;

  PKCS7_add_crl := LoadLibCryptoFunction('PKCS7_add_crl');
  FuncLoadError := not assigned(PKCS7_add_crl);
  if FuncLoadError then
  begin
    PKCS7_add_crl :=  @ERROR_PKCS7_add_crl;
  end;

  PKCS7_content_new := LoadLibCryptoFunction('PKCS7_content_new');
  FuncLoadError := not assigned(PKCS7_content_new);
  if FuncLoadError then
  begin
    PKCS7_content_new :=  @ERROR_PKCS7_content_new;
  end;

  PKCS7_dataVerify := LoadLibCryptoFunction('PKCS7_dataVerify');
  FuncLoadError := not assigned(PKCS7_dataVerify);
  if FuncLoadError then
  begin
    PKCS7_dataVerify :=  @ERROR_PKCS7_dataVerify;
  end;

  PKCS7_signatureVerify := LoadLibCryptoFunction('PKCS7_signatureVerify');
  FuncLoadError := not assigned(PKCS7_signatureVerify);
  if FuncLoadError then
  begin
    PKCS7_signatureVerify :=  @ERROR_PKCS7_signatureVerify;
  end;

  PKCS7_dataInit := LoadLibCryptoFunction('PKCS7_dataInit');
  FuncLoadError := not assigned(PKCS7_dataInit);
  if FuncLoadError then
  begin
    PKCS7_dataInit :=  @ERROR_PKCS7_dataInit;
  end;

  PKCS7_dataFinal := LoadLibCryptoFunction('PKCS7_dataFinal');
  FuncLoadError := not assigned(PKCS7_dataFinal);
  if FuncLoadError then
  begin
    PKCS7_dataFinal :=  @ERROR_PKCS7_dataFinal;
  end;

  PKCS7_dataDecode := LoadLibCryptoFunction('PKCS7_dataDecode');
  FuncLoadError := not assigned(PKCS7_dataDecode);
  if FuncLoadError then
  begin
    PKCS7_dataDecode :=  @ERROR_PKCS7_dataDecode;
  end;

  PKCS7_add_signature := LoadLibCryptoFunction('PKCS7_add_signature');
  FuncLoadError := not assigned(PKCS7_add_signature);
  if FuncLoadError then
  begin
    PKCS7_add_signature :=  @ERROR_PKCS7_add_signature;
  end;

  PKCS7_cert_from_signer_info := LoadLibCryptoFunction('PKCS7_cert_from_signer_info');
  FuncLoadError := not assigned(PKCS7_cert_from_signer_info);
  if FuncLoadError then
  begin
    PKCS7_cert_from_signer_info :=  @ERROR_PKCS7_cert_from_signer_info;
  end;

  PKCS7_set_digest := LoadLibCryptoFunction('PKCS7_set_digest');
  FuncLoadError := not assigned(PKCS7_set_digest);
  if FuncLoadError then
  begin
    PKCS7_set_digest :=  @ERROR_PKCS7_set_digest;
  end;

  PKCS7_add_recipient := LoadLibCryptoFunction('PKCS7_add_recipient');
  FuncLoadError := not assigned(PKCS7_add_recipient);
  if FuncLoadError then
  begin
    PKCS7_add_recipient :=  @ERROR_PKCS7_add_recipient;
  end;

  PKCS7_SIGNER_INFO_get0_algs := LoadLibCryptoFunction('PKCS7_SIGNER_INFO_get0_algs');
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_get0_algs);
  if FuncLoadError then
  begin
    PKCS7_SIGNER_INFO_get0_algs :=  @ERROR_PKCS7_SIGNER_INFO_get0_algs;
  end;

  PKCS7_RECIP_INFO_get0_alg := LoadLibCryptoFunction('PKCS7_RECIP_INFO_get0_alg');
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_get0_alg);
  if FuncLoadError then
  begin
    PKCS7_RECIP_INFO_get0_alg :=  @ERROR_PKCS7_RECIP_INFO_get0_alg;
  end;

  PKCS7_add_recipient_info := LoadLibCryptoFunction('PKCS7_add_recipient_info');
  FuncLoadError := not assigned(PKCS7_add_recipient_info);
  if FuncLoadError then
  begin
    PKCS7_add_recipient_info :=  @ERROR_PKCS7_add_recipient_info;
  end;

  PKCS7_RECIP_INFO_set := LoadLibCryptoFunction('PKCS7_RECIP_INFO_set');
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_set);
  if FuncLoadError then
  begin
    PKCS7_RECIP_INFO_set :=  @ERROR_PKCS7_RECIP_INFO_set;
  end;

  PKCS7_set_cipher := LoadLibCryptoFunction('PKCS7_set_cipher');
  FuncLoadError := not assigned(PKCS7_set_cipher);
  if FuncLoadError then
  begin
    PKCS7_set_cipher :=  @ERROR_PKCS7_set_cipher;
  end;

  PKCS7_stream := LoadLibCryptoFunction('PKCS7_stream');
  FuncLoadError := not assigned(PKCS7_stream);
  if FuncLoadError then
  begin
    PKCS7_stream :=  @ERROR_PKCS7_stream;
  end;

  PKCS7_get_issuer_and_serial := LoadLibCryptoFunction('PKCS7_get_issuer_and_serial');
  FuncLoadError := not assigned(PKCS7_get_issuer_and_serial);
  if FuncLoadError then
  begin
    PKCS7_get_issuer_and_serial :=  @ERROR_PKCS7_get_issuer_and_serial;
  end;

  PKCS7_add_signed_attribute := LoadLibCryptoFunction('PKCS7_add_signed_attribute');
  FuncLoadError := not assigned(PKCS7_add_signed_attribute);
  if FuncLoadError then
  begin
    PKCS7_add_signed_attribute :=  @ERROR_PKCS7_add_signed_attribute;
  end;

  PKCS7_add_attribute := LoadLibCryptoFunction('PKCS7_add_attribute');
  FuncLoadError := not assigned(PKCS7_add_attribute);
  if FuncLoadError then
  begin
    PKCS7_add_attribute :=  @ERROR_PKCS7_add_attribute;
  end;

  PKCS7_get_attribute := LoadLibCryptoFunction('PKCS7_get_attribute');
  FuncLoadError := not assigned(PKCS7_get_attribute);
  if FuncLoadError then
  begin
    PKCS7_get_attribute :=  @ERROR_PKCS7_get_attribute;
  end;

  PKCS7_get_signed_attribute := LoadLibCryptoFunction('PKCS7_get_signed_attribute');
  FuncLoadError := not assigned(PKCS7_get_signed_attribute);
  if FuncLoadError then
  begin
    PKCS7_get_signed_attribute :=  @ERROR_PKCS7_get_signed_attribute;
  end;

  PKCS7_sign_add_signer := LoadLibCryptoFunction('PKCS7_sign_add_signer');
  FuncLoadError := not assigned(PKCS7_sign_add_signer);
  if FuncLoadError then
  begin
    PKCS7_sign_add_signer :=  @ERROR_PKCS7_sign_add_signer;
  end;

  PKCS7_final := LoadLibCryptoFunction('PKCS7_final');
  FuncLoadError := not assigned(PKCS7_final);
  if FuncLoadError then
  begin
    PKCS7_final :=  @ERROR_PKCS7_final;
  end;

  PKCS7_decrypt := LoadLibCryptoFunction('PKCS7_decrypt');
  FuncLoadError := not assigned(PKCS7_decrypt);
  if FuncLoadError then
  begin
    PKCS7_decrypt :=  @ERROR_PKCS7_decrypt;
  end;

  PKCS7_add_attrib_content_type := LoadLibCryptoFunction('PKCS7_add_attrib_content_type');
  FuncLoadError := not assigned(PKCS7_add_attrib_content_type);
  if FuncLoadError then
  begin
    PKCS7_add_attrib_content_type :=  @ERROR_PKCS7_add_attrib_content_type;
  end;

  PKCS7_add0_attrib_signing_time := LoadLibCryptoFunction('PKCS7_add0_attrib_signing_time');
  FuncLoadError := not assigned(PKCS7_add0_attrib_signing_time);
  if FuncLoadError then
  begin
    PKCS7_add0_attrib_signing_time :=  @ERROR_PKCS7_add0_attrib_signing_time;
  end;

  PKCS7_add1_attrib_digest := LoadLibCryptoFunction('PKCS7_add1_attrib_digest');
  FuncLoadError := not assigned(PKCS7_add1_attrib_digest);
  if FuncLoadError then
  begin
    PKCS7_add1_attrib_digest :=  @ERROR_PKCS7_add1_attrib_digest;
  end;

  SMIME_write_PKCS7 := LoadLibCryptoFunction('SMIME_write_PKCS7');
  FuncLoadError := not assigned(SMIME_write_PKCS7);
  if FuncLoadError then
  begin
    SMIME_write_PKCS7 :=  @ERROR_SMIME_write_PKCS7;
  end;

  SMIME_read_PKCS7 := LoadLibCryptoFunction('SMIME_read_PKCS7');
  FuncLoadError := not assigned(SMIME_read_PKCS7);
  if FuncLoadError then
  begin
    SMIME_read_PKCS7 :=  @ERROR_SMIME_read_PKCS7;
  end;

  BIO_new_PKCS7 := LoadLibCryptoFunction('BIO_new_PKCS7');
  FuncLoadError := not assigned(BIO_new_PKCS7);
  if FuncLoadError then
  begin
    BIO_new_PKCS7 :=  @ERROR_BIO_new_PKCS7;
  end;

end;

procedure UnLoad;
begin
  PKCS7_ISSUER_AND_SERIAL_digest := nil;
  PKCS7_dup := nil;
  d2i_PKCS7_bio := nil;
  i2d_PKCS7_bio := nil;
  i2d_PKCS7_bio_stream := nil;
  PEM_write_bio_PKCS7_stream := nil;
  PKCS7_ctrl := nil;
  PKCS7_set_type := nil;
  PKCS7_set0_type_other := nil;
  PKCS7_set_content := nil;
  PKCS7_SIGNER_INFO_set := nil;
  PKCS7_SIGNER_INFO_sign := nil;
  PKCS7_add_signer := nil;
  PKCS7_add_certificate := nil;
  PKCS7_add_crl := nil;
  PKCS7_content_new := nil;
  PKCS7_dataVerify := nil;
  PKCS7_signatureVerify := nil;
  PKCS7_dataInit := nil;
  PKCS7_dataFinal := nil;
  PKCS7_dataDecode := nil;
  PKCS7_add_signature := nil;
  PKCS7_cert_from_signer_info := nil;
  PKCS7_set_digest := nil;
  PKCS7_add_recipient := nil;
  PKCS7_SIGNER_INFO_get0_algs := nil;
  PKCS7_RECIP_INFO_get0_alg := nil;
  PKCS7_add_recipient_info := nil;
  PKCS7_RECIP_INFO_set := nil;
  PKCS7_set_cipher := nil;
  PKCS7_stream := nil;
  PKCS7_get_issuer_and_serial := nil;
  PKCS7_add_signed_attribute := nil;
  PKCS7_add_attribute := nil;
  PKCS7_get_attribute := nil;
  PKCS7_get_signed_attribute := nil;
  PKCS7_sign_add_signer := nil;
  PKCS7_final := nil;
  PKCS7_decrypt := nil;
  PKCS7_add_attrib_content_type := nil;
  PKCS7_add0_attrib_signing_time := nil;
  PKCS7_add1_attrib_digest := nil;
  SMIME_write_PKCS7 := nil;
  SMIME_read_PKCS7 := nil;
  BIO_new_PKCS7 := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
