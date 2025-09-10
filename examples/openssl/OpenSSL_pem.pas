(* This unit was generated from the source file pem.h2pas 
It should not be modified directly. All changes should be made to pem.h2pas
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


unit OpenSSL_pem;


interface

// Headers for OpenSSL 1.1.1
// pem.h


uses
  OpenSSLAPI,
  OpenSSL_ec,
  OpenSSL_ossl_typ,
  OpenSSL_pkcs7,
  OpenSSL_x509;
  
type
  EVP_CIPHER_INFO = type Pointer;
  PEVP_CIPHER_INFO = ^EVP_CIPHER_INFO;

const
  PEM_BUFSIZE             = 1024;

  PEM_STRING_X509_OLD     = AnsiString('X509 CERTIFICATE');
  PEM_STRING_X509         = AnsiString('CERTIFICATE');
  PEM_STRING_X509_TRUSTED = AnsiString('TRUSTED CERTIFICATE');
  PEM_STRING_X509_REQ_OLD = AnsiString('NEW CERTIFICATE REQUEST');
  PEM_STRING_X509_REQ     = AnsiString('CERTIFICATE REQUEST');
  PEM_STRING_X509_CRL     = AnsiString('X509 CRL');
  PEM_STRING_EVP_PKEY     = AnsiString('ANY PRIVATE KEY');
  PEM_STRING_PUBLIC       = AnsiString('PUBLIC KEY');
  PEM_STRING_RSA          = AnsiString('RSA PRIVATE KEY');
  PEM_STRING_RSA_PUBLIC   = AnsiString('RSA PUBLIC KEY');
  PEM_STRING_DSA          = AnsiString('DSA PRIVATE KEY');
  PEM_STRING_DSA_PUBLIC   = AnsiString('DSA PUBLIC KEY');
  PEM_STRING_PKCS7        = AnsiString('PKCS7');
  PEM_STRING_PKCS7_SIGNED = AnsiString('PKCS #7 SIGNED DATA');
  PEM_STRING_PKCS8        = AnsiString('ENCRYPTED PRIVATE KEY');
  PEM_STRING_PKCS8INF     = AnsiString('PRIVATE KEY');
  PEM_STRING_DHPARAMS     = AnsiString('DH PARAMETERS');
  PEM_STRING_DHXPARAMS    = AnsiString('X9.42 DH PARAMETERS');
  PEM_STRING_SSL_SESSION  = AnsiString('SSL SESSION PARAMETERS');
  PEM_STRING_DSAPARAMS    = AnsiString('DSA PARAMETERS');
  PEM_STRING_ECDSA_PUBLIC = AnsiString('ECDSA PUBLIC KEY');
  PEM_STRING_ECPARAMETERS = AnsiString('EC PARAMETERS');
  PEM_STRING_ECPRIVATEKEY = AnsiString('EC PRIVATE KEY');
  PEM_STRING_PARAMETERS   = AnsiString('PARAMETERS');
  PEM_STRING_CMS          = AnsiString('CMS');

  PEM_TYPE_ENCRYPTED      = 10;
  PEM_TYPE_MIC_ONLY       = 20;
  PEM_TYPE_MIC_CLEAR      = 30;
  PEM_TYPE_CLEAR          = 40;

  PEM_FLAG_SECURE         = $1;
  PEM_FLAG_EAY_COMPATIBLE = $2;
  PEM_FLAG_ONLY_B64       = $4;

  {Reason Codes}
  PEM_R_BAD_BASE64_DECODE			= 100;
  PEM_R_BAD_DECRYPT				= 101;
  PEM_R_BAD_END_LINE				= 102;
  PEM_R_BAD_IV_CHARS				= 103;
  PEM_R_BAD_MAGIC_NUMBER			= 116;
  PEM_R_BAD_PASSWORD_READ			= 104;
  PEM_R_BAD_VERSION_NUMBER			= 117;
  PEM_R_BIO_WRITE_FAILURE			= 118;
  PEM_R_CIPHER_IS_NULL				= 127;
  PEM_R_ERROR_CONVERTING_PRIVATE_KEY		= 115;
  PEM_R_EXPECTING_PRIVATE_KEY_BLOB		= 119;
  PEM_R_EXPECTING_PUBLIC_KEY_BLOB		= 120;
  PEM_R_HEADER_TOO_LONG				= 128;
  PEM_R_INCONSISTENT_HEADER			= 121;
  PEM_R_KEYBLOB_HEADER_PARSE_ERROR		= 122;
  PEM_R_KEYBLOB_TOO_SHORT			= 123;
  PEM_R_NOT_DEK_INFO				= 105;
  PEM_R_NOT_ENCRYPTED				= 106;
  PEM_R_NOT_PROC_TYPE				= 107;
  PEM_R_NO_START_LINE				= 108;
  PEM_R_PROBLEMS_GETTING_PASSWORD	        = 109;
  PEM_R_PUBLIC_KEY_NO_RSA			= 110;
  PEM_R_PVK_DATA_TOO_SHORT		        = 124;
  PEM_R_PVK_TOO_SHORT				= 125;
  PEM_R_READ_KEY				= 111;
  PEM_R_SHORT_HEADER				= 112;
  PEM_R_UNSUPPORTED_CIPHER			= 113;
  PEM_R_UNSUPPORTED_ENCRYPTION			= 114;

type
  PSTACK_OF_X509_INFO = pointer;
  pem_password_cb = function(buf: PAnsiChar; size: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM PEM_get_EVP_CIPHER_INFO}
{$EXTERNALSYM PEM_do_header}
{$EXTERNALSYM PEM_read_bio}
{$EXTERNALSYM PEM_read_bio_ex}
{$EXTERNALSYM PEM_bytes_read_bio_secmem}
{$EXTERNALSYM PEM_write_bio}
{$EXTERNALSYM PEM_bytes_read_bio}
{$EXTERNALSYM PEM_ASN1_read_bio}
{$EXTERNALSYM PEM_ASN1_write_bio}
{$EXTERNALSYM PEM_X509_INFO_read_bio}
{$EXTERNALSYM PEM_X509_INFO_write_bio}
{$EXTERNALSYM PEM_SignInit}
{$EXTERNALSYM PEM_SignUpdate}
{$EXTERNALSYM PEM_SignFinal}
{$EXTERNALSYM PEM_def_callback}
{$EXTERNALSYM PEM_proc_type}
{$EXTERNALSYM PEM_dek_info}
{$EXTERNALSYM PEM_read_bio_X509}
{$EXTERNALSYM PEM_write_bio_X509}
{$EXTERNALSYM PEM_read_bio_X509_AUX}
{$EXTERNALSYM PEM_write_bio_X509_AUX}
{$EXTERNALSYM PEM_read_bio_X509_REQ}
{$EXTERNALSYM PEM_write_bio_X509_REQ}
{$EXTERNALSYM PEM_write_bio_X509_REQ_NEW}
{$EXTERNALSYM PEM_read_bio_X509_CRL}
{$EXTERNALSYM PEM_write_bio_X509_CRL}
{$EXTERNALSYM PEM_read_bio_PKCS7}
{$EXTERNALSYM PEM_write_bio_PKCS7}
{$EXTERNALSYM PEM_read_bio_PKCS8}
{$EXTERNALSYM PEM_write_bio_PKCS8}
{$EXTERNALSYM PEM_read_bio_PKCS8_PRIV_KEY_INFO}
{$EXTERNALSYM PEM_write_bio_PKCS8_PRIV_KEY_INFO}
{$EXTERNALSYM PEM_read_bio_RSAPrivateKey}
{$EXTERNALSYM PEM_write_bio_RSAPrivateKey}
{$EXTERNALSYM PEM_read_bio_RSAPublicKey}
{$EXTERNALSYM PEM_write_bio_RSAPublicKey}
{$EXTERNALSYM PEM_read_bio_RSA_PUBKEY}
{$EXTERNALSYM PEM_write_bio_RSA_PUBKEY}
{$EXTERNALSYM PEM_read_bio_DSAPrivateKey}
{$EXTERNALSYM PEM_write_bio_DSAPrivateKey}
{$EXTERNALSYM PEM_read_bio_DSA_PUBKEY}
{$EXTERNALSYM PEM_write_bio_DSA_PUBKEY}
{$EXTERNALSYM PEM_read_bio_DSAparams}
{$EXTERNALSYM PEM_write_bio_DSAparams}
{$EXTERNALSYM PEM_read_bio_ECPKParameters}
{$EXTERNALSYM PEM_write_bio_ECPKParameters}
{$EXTERNALSYM PEM_read_bio_ECPrivateKey}
{$EXTERNALSYM PEM_write_bio_ECPrivateKey}
{$EXTERNALSYM PEM_read_bio_EC_PUBKEY}
{$EXTERNALSYM PEM_write_bio_EC_PUBKEY}
{$EXTERNALSYM PEM_read_bio_DHparams}
{$EXTERNALSYM PEM_write_bio_DHparams}
{$EXTERNALSYM PEM_write_bio_DHxparams}
{$EXTERNALSYM PEM_read_bio_PrivateKey}
{$EXTERNALSYM PEM_write_bio_PrivateKey}
{$EXTERNALSYM PEM_read_bio_PUBKEY}
{$EXTERNALSYM PEM_write_bio_PUBKEY}
{$EXTERNALSYM PEM_write_bio_PrivateKey_traditional}
{$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey_nid}
{$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey}
{$EXTERNALSYM i2d_PKCS8PrivateKey_bio}
{$EXTERNALSYM i2d_PKCS8PrivateKey_nid_bio}
{$EXTERNALSYM d2i_PKCS8PrivateKey_bio}
{$EXTERNALSYM PEM_read_bio_Parameters}
{$EXTERNALSYM PEM_write_bio_Parameters}
{$EXTERNALSYM b2i_PrivateKey}
{$EXTERNALSYM b2i_PublicKey}
{$EXTERNALSYM b2i_PrivateKey_bio}
{$EXTERNALSYM b2i_PublicKey_bio}
{$EXTERNALSYM i2b_PrivateKey_bio}
{$EXTERNALSYM i2b_PublicKey_bio}
{$EXTERNALSYM b2i_PVK_bio}
{$EXTERNALSYM i2b_PVK_bio}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PByte; len: POpenSSL_C_LONG; callback: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_bytes_read_bio_secmem(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio(bp: PBIO; const name: PAnsiChar; const hdr: PAnsiChar; const data: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_bytes_read_bio(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_ASN1_read_bio(d2i: d2i_of_void; const name: PAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl; external CLibCrypto;
function PEM_ASN1_write_bio(i2d: i2d_of_void; const name: PAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_X509_INFO_read_bio(bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl; external CLibCrypto;
function PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cd: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure PEM_dek_info(buf: PAnsiChar; const type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl; external CLibCrypto;
function PEM_read_bio_X509(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl; external CLibCrypto;
function PEM_write_bio_X509(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_X509_AUX(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl; external CLibCrypto;
function PEM_write_bio_X509_AUX(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_X509_REQ(bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl; external CLibCrypto;
function PEM_write_bio_X509_REQ(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_X509_REQ_NEW(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_X509_CRL(bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl; external CLibCrypto;
function PEM_write_bio_X509_CRL(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PKCS7(bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS7(bp: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PKCS8(bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8(bp: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_RSAPrivateKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl; external CLibCrypto;
function PEM_write_bio_RSAPrivateKey(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_RSAPublicKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl; external CLibCrypto;
function PEM_write_bio_RSAPublicKey(bp: PBIO; const x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_RSA_PUBKEY(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl; external CLibCrypto;
function PEM_write_bio_RSA_PUBKEY(bp: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DSAPrivateKey(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl; external CLibCrypto;
function PEM_write_bio_DSAPrivateKey(bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DSA_PUBKEY(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl; external CLibCrypto;
function PEM_write_bio_DSA_PUBKEY(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DSAparams(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl; external CLibCrypto;
function PEM_write_bio_DSAparams(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_ECPKParameters(bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl; external CLibCrypto;
function PEM_write_bio_ECPKParameters(bp: PBIO; const x: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_ECPrivateKey(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl; external CLibCrypto;
function PEM_write_bio_ECPrivateKey(bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_EC_PUBKEY(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl; external CLibCrypto;
function PEM_write_bio_EC_PUBKEY(bp: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DHparams(bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl; external CLibCrypto;
function PEM_write_bio_DHparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_DHxparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PrivateKey(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_write_bio_PrivateKey(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PUBKEY(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_write_bio_PUBKEY(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8PrivateKey(bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function b2i_PrivateKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function b2i_PublicKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl; external CLibCrypto;
function b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl; external CLibCrypto;
function i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function b2i_PVK_bio(in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  PEM_get_EVP_CIPHER_INFO: function (header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl = nil;
  PEM_do_header: function (cipher: PEVP_CIPHER_INFO; data: PByte; len: POpenSSL_C_LONG; callback: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio: function (bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_ex: function (bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  PEM_bytes_read_bio_secmem: function (pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio: function (bp: PBIO; const name: PAnsiChar; const hdr: PAnsiChar; const data: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  PEM_bytes_read_bio: function (pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_ASN1_read_bio: function (d2i: d2i_of_void; const name: PAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl = nil;
  PEM_ASN1_write_bio: function (i2d: i2d_of_void; const name: PAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_X509_INFO_read_bio: function (bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl = nil;
  PEM_X509_INFO_write_bio: function (bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cd: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_SignInit: function (ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  PEM_SignUpdate: function (ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TOpenSSL_C_INT; cdecl = nil;
  PEM_SignFinal: function (ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  PEM_def_callback: function (buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_proc_type: procedure (buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl = nil;
  PEM_dek_info: procedure (buf: PAnsiChar; const type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl = nil;
  PEM_read_bio_X509: function (bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl = nil;
  PEM_write_bio_X509: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_X509_AUX: function (bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl = nil;
  PEM_write_bio_X509_AUX: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_X509_REQ: function (bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl = nil;
  PEM_write_bio_X509_REQ: function (bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_X509_REQ_NEW: function (bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_X509_CRL: function (bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl = nil;
  PEM_write_bio_X509_CRL: function (bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_PKCS7: function (bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl = nil;
  PEM_write_bio_PKCS7: function (bp: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_PKCS8: function (bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl = nil;
  PEM_write_bio_PKCS8: function (bp: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO: function (bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO: function (bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_RSAPrivateKey: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSAPrivateKey: function (bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_RSAPublicKey: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSAPublicKey: function (bp: PBIO; const x: PRSA): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_RSA_PUBKEY: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSA_PUBKEY: function (bp: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_DSAPrivateKey: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = nil;
  PEM_write_bio_DSAPrivateKey: function (bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_DSA_PUBKEY: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = nil;
  PEM_write_bio_DSA_PUBKEY: function (bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_DSAparams: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = nil;
  PEM_write_bio_DSAparams: function (bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_ECPKParameters: function (bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl = nil;
  PEM_write_bio_ECPKParameters: function (bp: PBIO; const x: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_ECPrivateKey: function (bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl = nil;
  PEM_write_bio_ECPrivateKey: function (bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_EC_PUBKEY: function (bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl = nil;
  PEM_write_bio_EC_PUBKEY: function (bp: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_DHparams: function (bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl = nil;
  PEM_write_bio_DHparams: function (bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_DHxparams: function (bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_PrivateKey: function (bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  PEM_write_bio_PrivateKey: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_read_bio_PUBKEY: function (bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  PEM_write_bio_PUBKEY: function (bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_PrivateKey_traditional: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_PKCS8PrivateKey_nid: function (bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_PKCS8PrivateKey: function (bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  i2d_PKCS8PrivateKey_bio: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  i2d_PKCS8PrivateKey_nid_bio: function (bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
  d2i_PKCS8PrivateKey_bio: function (bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  PEM_read_bio_Parameters: function (bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  PEM_write_bio_Parameters: function (bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  b2i_PrivateKey: function (const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = nil;
  b2i_PublicKey: function (const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = nil;
  b2i_PrivateKey_bio: function (in_: PBIO): PEVP_PKEY; cdecl = nil;
  b2i_PublicKey_bio: function (in_: PBIO): PEVP_PKEY; cdecl = nil;
  i2b_PrivateKey_bio: function (out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  i2b_PublicKey_bio: function (out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  b2i_PVK_bio: function (in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  i2b_PVK_bio: function (out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = nil;
{$ENDIF}
const
  PEM_read_bio_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PEM_bytes_read_bio_secmem_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PEM_write_bio_PrivateKey_traditional_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function ERROR_PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_get_EVP_CIPHER_INFO');
end;

function ERROR_PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PByte; len: POpenSSL_C_LONG; callback: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_do_header');
end;

function ERROR_PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio');
end;

function ERROR_PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ex');
end;

function ERROR_PEM_bytes_read_bio_secmem(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_bytes_read_bio_secmem');
end;

function ERROR_PEM_write_bio(bp: PBIO; const name: PAnsiChar; const hdr: PAnsiChar; const data: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio');
end;

function ERROR_PEM_bytes_read_bio(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_bytes_read_bio');
end;

function ERROR_PEM_ASN1_read_bio(d2i: d2i_of_void; const name: PAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_read_bio');
end;

function ERROR_PEM_ASN1_write_bio(i2d: i2d_of_void; const name: PAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_write_bio');
end;

function ERROR_PEM_X509_INFO_read_bio(bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_read_bio');
end;

function ERROR_PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cd: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_write_bio');
end;

function ERROR_PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignInit');
end;

function ERROR_PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignUpdate');
end;

function ERROR_PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignFinal');
end;

function ERROR_PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_def_callback');
end;

procedure ERROR_PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_proc_type');
end;

procedure ERROR_PEM_dek_info(buf: PAnsiChar; const type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_dek_info');
end;

function ERROR_PEM_read_bio_X509(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509');
end;

function ERROR_PEM_write_bio_X509(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509');
end;

function ERROR_PEM_read_bio_X509_AUX(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_AUX');
end;

function ERROR_PEM_write_bio_X509_AUX(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_AUX');
end;

function ERROR_PEM_read_bio_X509_REQ(bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_REQ');
end;

function ERROR_PEM_write_bio_X509_REQ(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_REQ');
end;

function ERROR_PEM_write_bio_X509_REQ_NEW(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_REQ_NEW');
end;

function ERROR_PEM_read_bio_X509_CRL(bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_CRL');
end;

function ERROR_PEM_write_bio_X509_CRL(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_CRL');
end;

function ERROR_PEM_read_bio_PKCS7(bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS7');
end;

function ERROR_PEM_write_bio_PKCS7(bp: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS7');
end;

function ERROR_PEM_read_bio_PKCS8(bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS8');
end;

function ERROR_PEM_write_bio_PKCS8(bp: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8');
end;

function ERROR_PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
end;

function ERROR_PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
end;

function ERROR_PEM_read_bio_RSAPrivateKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSAPrivateKey');
end;

function ERROR_PEM_write_bio_RSAPrivateKey(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSAPrivateKey');
end;

function ERROR_PEM_read_bio_RSAPublicKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSAPublicKey');
end;

function ERROR_PEM_write_bio_RSAPublicKey(bp: PBIO; const x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSAPublicKey');
end;

function ERROR_PEM_read_bio_RSA_PUBKEY(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSA_PUBKEY');
end;

function ERROR_PEM_write_bio_RSA_PUBKEY(bp: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSA_PUBKEY');
end;

function ERROR_PEM_read_bio_DSAPrivateKey(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSAPrivateKey');
end;

function ERROR_PEM_write_bio_DSAPrivateKey(bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSAPrivateKey');
end;

function ERROR_PEM_read_bio_DSA_PUBKEY(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSA_PUBKEY');
end;

function ERROR_PEM_write_bio_DSA_PUBKEY(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSA_PUBKEY');
end;

function ERROR_PEM_read_bio_DSAparams(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSAparams');
end;

function ERROR_PEM_write_bio_DSAparams(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSAparams');
end;

function ERROR_PEM_read_bio_ECPKParameters(bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ECPKParameters');
end;

function ERROR_PEM_write_bio_ECPKParameters(bp: PBIO; const x: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ECPKParameters');
end;

function ERROR_PEM_read_bio_ECPrivateKey(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ECPrivateKey');
end;

function ERROR_PEM_write_bio_ECPrivateKey(bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ECPrivateKey');
end;

function ERROR_PEM_read_bio_EC_PUBKEY(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_EC_PUBKEY');
end;

function ERROR_PEM_write_bio_EC_PUBKEY(bp: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_EC_PUBKEY');
end;

function ERROR_PEM_read_bio_DHparams(bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DHparams');
end;

function ERROR_PEM_write_bio_DHparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DHparams');
end;

function ERROR_PEM_write_bio_DHxparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DHxparams');
end;

function ERROR_PEM_read_bio_PrivateKey(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PrivateKey');
end;

function ERROR_PEM_write_bio_PrivateKey(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PrivateKey');
end;

function ERROR_PEM_read_bio_PUBKEY(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PUBKEY');
end;

function ERROR_PEM_write_bio_PUBKEY(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PUBKEY');
end;

function ERROR_PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PrivateKey_traditional');
end;

function ERROR_PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8PrivateKey_nid');
end;

function ERROR_PEM_write_bio_PKCS8PrivateKey(bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8PrivateKey');
end;

function ERROR_i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_bio');
end;

function ERROR_i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_nid_bio');
end;

function ERROR_d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8PrivateKey_bio');
end;

function ERROR_PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_Parameters');
end;

function ERROR_PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_Parameters');
end;

function ERROR_b2i_PrivateKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PrivateKey');
end;

function ERROR_b2i_PublicKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PublicKey');
end;

function ERROR_b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PrivateKey_bio');
end;

function ERROR_b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PublicKey_bio');
end;

function ERROR_i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PrivateKey_bio');
end;

function ERROR_i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PublicKey_bio');
end;

function ERROR_b2i_PVK_bio(in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PVK_bio');
end;

function ERROR_i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PVK_bio');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  PEM_get_EVP_CIPHER_INFO := LoadLibCryptoFunction('PEM_get_EVP_CIPHER_INFO');
  FuncLoadError := not assigned(PEM_get_EVP_CIPHER_INFO);
  if FuncLoadError then
  begin
    PEM_get_EVP_CIPHER_INFO :=  @ERROR_PEM_get_EVP_CIPHER_INFO;
  end;

  PEM_do_header := LoadLibCryptoFunction('PEM_do_header');
  FuncLoadError := not assigned(PEM_do_header);
  if FuncLoadError then
  begin
    PEM_do_header :=  @ERROR_PEM_do_header;
  end;

  PEM_read_bio := LoadLibCryptoFunction('PEM_read_bio');
  FuncLoadError := not assigned(PEM_read_bio);
  if FuncLoadError then
  begin
    PEM_read_bio :=  @ERROR_PEM_read_bio;
  end;

  PEM_read_bio_ex := LoadLibCryptoFunction('PEM_read_bio_ex');
  FuncLoadError := not assigned(PEM_read_bio_ex);
  if FuncLoadError then
  begin
    PEM_read_bio_ex :=  @ERROR_PEM_read_bio_ex;
  end;

  PEM_bytes_read_bio_secmem := LoadLibCryptoFunction('PEM_bytes_read_bio_secmem');
  FuncLoadError := not assigned(PEM_bytes_read_bio_secmem);
  if FuncLoadError then
  begin
    PEM_bytes_read_bio_secmem :=  @ERROR_PEM_bytes_read_bio_secmem;
  end;

  PEM_write_bio := LoadLibCryptoFunction('PEM_write_bio');
  FuncLoadError := not assigned(PEM_write_bio);
  if FuncLoadError then
  begin
    PEM_write_bio :=  @ERROR_PEM_write_bio;
  end;

  PEM_bytes_read_bio := LoadLibCryptoFunction('PEM_bytes_read_bio');
  FuncLoadError := not assigned(PEM_bytes_read_bio);
  if FuncLoadError then
  begin
    PEM_bytes_read_bio :=  @ERROR_PEM_bytes_read_bio;
  end;

  PEM_ASN1_read_bio := LoadLibCryptoFunction('PEM_ASN1_read_bio');
  FuncLoadError := not assigned(PEM_ASN1_read_bio);
  if FuncLoadError then
  begin
    PEM_ASN1_read_bio :=  @ERROR_PEM_ASN1_read_bio;
  end;

  PEM_ASN1_write_bio := LoadLibCryptoFunction('PEM_ASN1_write_bio');
  FuncLoadError := not assigned(PEM_ASN1_write_bio);
  if FuncLoadError then
  begin
    PEM_ASN1_write_bio :=  @ERROR_PEM_ASN1_write_bio;
  end;

  PEM_X509_INFO_read_bio := LoadLibCryptoFunction('PEM_X509_INFO_read_bio');
  FuncLoadError := not assigned(PEM_X509_INFO_read_bio);
  if FuncLoadError then
  begin
    PEM_X509_INFO_read_bio :=  @ERROR_PEM_X509_INFO_read_bio;
  end;

  PEM_X509_INFO_write_bio := LoadLibCryptoFunction('PEM_X509_INFO_write_bio');
  FuncLoadError := not assigned(PEM_X509_INFO_write_bio);
  if FuncLoadError then
  begin
    PEM_X509_INFO_write_bio :=  @ERROR_PEM_X509_INFO_write_bio;
  end;

  PEM_SignInit := LoadLibCryptoFunction('PEM_SignInit');
  FuncLoadError := not assigned(PEM_SignInit);
  if FuncLoadError then
  begin
    PEM_SignInit :=  @ERROR_PEM_SignInit;
  end;

  PEM_SignUpdate := LoadLibCryptoFunction('PEM_SignUpdate');
  FuncLoadError := not assigned(PEM_SignUpdate);
  if FuncLoadError then
  begin
    PEM_SignUpdate :=  @ERROR_PEM_SignUpdate;
  end;

  PEM_SignFinal := LoadLibCryptoFunction('PEM_SignFinal');
  FuncLoadError := not assigned(PEM_SignFinal);
  if FuncLoadError then
  begin
    PEM_SignFinal :=  @ERROR_PEM_SignFinal;
  end;

  PEM_def_callback := LoadLibCryptoFunction('PEM_def_callback');
  FuncLoadError := not assigned(PEM_def_callback);
  if FuncLoadError then
  begin
    PEM_def_callback :=  @ERROR_PEM_def_callback;
  end;

  PEM_proc_type := LoadLibCryptoFunction('PEM_proc_type');
  FuncLoadError := not assigned(PEM_proc_type);
  if FuncLoadError then
  begin
    PEM_proc_type :=  @ERROR_PEM_proc_type;
  end;

  PEM_dek_info := LoadLibCryptoFunction('PEM_dek_info');
  FuncLoadError := not assigned(PEM_dek_info);
  if FuncLoadError then
  begin
    PEM_dek_info :=  @ERROR_PEM_dek_info;
  end;

  PEM_read_bio_X509 := LoadLibCryptoFunction('PEM_read_bio_X509');
  FuncLoadError := not assigned(PEM_read_bio_X509);
  if FuncLoadError then
  begin
    PEM_read_bio_X509 :=  @ERROR_PEM_read_bio_X509;
  end;

  PEM_write_bio_X509 := LoadLibCryptoFunction('PEM_write_bio_X509');
  FuncLoadError := not assigned(PEM_write_bio_X509);
  if FuncLoadError then
  begin
    PEM_write_bio_X509 :=  @ERROR_PEM_write_bio_X509;
  end;

  PEM_read_bio_X509_AUX := LoadLibCryptoFunction('PEM_read_bio_X509_AUX');
  FuncLoadError := not assigned(PEM_read_bio_X509_AUX);
  if FuncLoadError then
  begin
    PEM_read_bio_X509_AUX :=  @ERROR_PEM_read_bio_X509_AUX;
  end;

  PEM_write_bio_X509_AUX := LoadLibCryptoFunction('PEM_write_bio_X509_AUX');
  FuncLoadError := not assigned(PEM_write_bio_X509_AUX);
  if FuncLoadError then
  begin
    PEM_write_bio_X509_AUX :=  @ERROR_PEM_write_bio_X509_AUX;
  end;

  PEM_read_bio_X509_REQ := LoadLibCryptoFunction('PEM_read_bio_X509_REQ');
  FuncLoadError := not assigned(PEM_read_bio_X509_REQ);
  if FuncLoadError then
  begin
    PEM_read_bio_X509_REQ :=  @ERROR_PEM_read_bio_X509_REQ;
  end;

  PEM_write_bio_X509_REQ := LoadLibCryptoFunction('PEM_write_bio_X509_REQ');
  FuncLoadError := not assigned(PEM_write_bio_X509_REQ);
  if FuncLoadError then
  begin
    PEM_write_bio_X509_REQ :=  @ERROR_PEM_write_bio_X509_REQ;
  end;

  PEM_write_bio_X509_REQ_NEW := LoadLibCryptoFunction('PEM_write_bio_X509_REQ_NEW');
  FuncLoadError := not assigned(PEM_write_bio_X509_REQ_NEW);
  if FuncLoadError then
  begin
    PEM_write_bio_X509_REQ_NEW :=  @ERROR_PEM_write_bio_X509_REQ_NEW;
  end;

  PEM_read_bio_X509_CRL := LoadLibCryptoFunction('PEM_read_bio_X509_CRL');
  FuncLoadError := not assigned(PEM_read_bio_X509_CRL);
  if FuncLoadError then
  begin
    PEM_read_bio_X509_CRL :=  @ERROR_PEM_read_bio_X509_CRL;
  end;

  PEM_write_bio_X509_CRL := LoadLibCryptoFunction('PEM_write_bio_X509_CRL');
  FuncLoadError := not assigned(PEM_write_bio_X509_CRL);
  if FuncLoadError then
  begin
    PEM_write_bio_X509_CRL :=  @ERROR_PEM_write_bio_X509_CRL;
  end;

  PEM_read_bio_PKCS7 := LoadLibCryptoFunction('PEM_read_bio_PKCS7');
  FuncLoadError := not assigned(PEM_read_bio_PKCS7);
  if FuncLoadError then
  begin
    PEM_read_bio_PKCS7 :=  @ERROR_PEM_read_bio_PKCS7;
  end;

  PEM_write_bio_PKCS7 := LoadLibCryptoFunction('PEM_write_bio_PKCS7');
  FuncLoadError := not assigned(PEM_write_bio_PKCS7);
  if FuncLoadError then
  begin
    PEM_write_bio_PKCS7 :=  @ERROR_PEM_write_bio_PKCS7;
  end;

  PEM_read_bio_PKCS8 := LoadLibCryptoFunction('PEM_read_bio_PKCS8');
  FuncLoadError := not assigned(PEM_read_bio_PKCS8);
  if FuncLoadError then
  begin
    PEM_read_bio_PKCS8 :=  @ERROR_PEM_read_bio_PKCS8;
  end;

  PEM_write_bio_PKCS8 := LoadLibCryptoFunction('PEM_write_bio_PKCS8');
  FuncLoadError := not assigned(PEM_write_bio_PKCS8);
  if FuncLoadError then
  begin
    PEM_write_bio_PKCS8 :=  @ERROR_PEM_write_bio_PKCS8;
  end;

  PEM_read_bio_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
  FuncLoadError := not assigned(PEM_read_bio_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    PEM_read_bio_PKCS8_PRIV_KEY_INFO :=  @ERROR_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
  end;

  PEM_write_bio_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
  FuncLoadError := not assigned(PEM_write_bio_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    PEM_write_bio_PKCS8_PRIV_KEY_INFO :=  @ERROR_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
  end;

  PEM_read_bio_RSAPrivateKey := LoadLibCryptoFunction('PEM_read_bio_RSAPrivateKey');
  FuncLoadError := not assigned(PEM_read_bio_RSAPrivateKey);
  if FuncLoadError then
  begin
    PEM_read_bio_RSAPrivateKey :=  @ERROR_PEM_read_bio_RSAPrivateKey;
  end;

  PEM_write_bio_RSAPrivateKey := LoadLibCryptoFunction('PEM_write_bio_RSAPrivateKey');
  FuncLoadError := not assigned(PEM_write_bio_RSAPrivateKey);
  if FuncLoadError then
  begin
    PEM_write_bio_RSAPrivateKey :=  @ERROR_PEM_write_bio_RSAPrivateKey;
  end;

  PEM_read_bio_RSAPublicKey := LoadLibCryptoFunction('PEM_read_bio_RSAPublicKey');
  FuncLoadError := not assigned(PEM_read_bio_RSAPublicKey);
  if FuncLoadError then
  begin
    PEM_read_bio_RSAPublicKey :=  @ERROR_PEM_read_bio_RSAPublicKey;
  end;

  PEM_write_bio_RSAPublicKey := LoadLibCryptoFunction('PEM_write_bio_RSAPublicKey');
  FuncLoadError := not assigned(PEM_write_bio_RSAPublicKey);
  if FuncLoadError then
  begin
    PEM_write_bio_RSAPublicKey :=  @ERROR_PEM_write_bio_RSAPublicKey;
  end;

  PEM_read_bio_RSA_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_RSA_PUBKEY');
  FuncLoadError := not assigned(PEM_read_bio_RSA_PUBKEY);
  if FuncLoadError then
  begin
    PEM_read_bio_RSA_PUBKEY :=  @ERROR_PEM_read_bio_RSA_PUBKEY;
  end;

  PEM_write_bio_RSA_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_RSA_PUBKEY');
  FuncLoadError := not assigned(PEM_write_bio_RSA_PUBKEY);
  if FuncLoadError then
  begin
    PEM_write_bio_RSA_PUBKEY :=  @ERROR_PEM_write_bio_RSA_PUBKEY;
  end;

  PEM_read_bio_DSAPrivateKey := LoadLibCryptoFunction('PEM_read_bio_DSAPrivateKey');
  FuncLoadError := not assigned(PEM_read_bio_DSAPrivateKey);
  if FuncLoadError then
  begin
    PEM_read_bio_DSAPrivateKey :=  @ERROR_PEM_read_bio_DSAPrivateKey;
  end;

  PEM_write_bio_DSAPrivateKey := LoadLibCryptoFunction('PEM_write_bio_DSAPrivateKey');
  FuncLoadError := not assigned(PEM_write_bio_DSAPrivateKey);
  if FuncLoadError then
  begin
    PEM_write_bio_DSAPrivateKey :=  @ERROR_PEM_write_bio_DSAPrivateKey;
  end;

  PEM_read_bio_DSA_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_DSA_PUBKEY');
  FuncLoadError := not assigned(PEM_read_bio_DSA_PUBKEY);
  if FuncLoadError then
  begin
    PEM_read_bio_DSA_PUBKEY :=  @ERROR_PEM_read_bio_DSA_PUBKEY;
  end;

  PEM_write_bio_DSA_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_DSA_PUBKEY');
  FuncLoadError := not assigned(PEM_write_bio_DSA_PUBKEY);
  if FuncLoadError then
  begin
    PEM_write_bio_DSA_PUBKEY :=  @ERROR_PEM_write_bio_DSA_PUBKEY;
  end;

  PEM_read_bio_DSAparams := LoadLibCryptoFunction('PEM_read_bio_DSAparams');
  FuncLoadError := not assigned(PEM_read_bio_DSAparams);
  if FuncLoadError then
  begin
    PEM_read_bio_DSAparams :=  @ERROR_PEM_read_bio_DSAparams;
  end;

  PEM_write_bio_DSAparams := LoadLibCryptoFunction('PEM_write_bio_DSAparams');
  FuncLoadError := not assigned(PEM_write_bio_DSAparams);
  if FuncLoadError then
  begin
    PEM_write_bio_DSAparams :=  @ERROR_PEM_write_bio_DSAparams;
  end;

  PEM_read_bio_ECPKParameters := LoadLibCryptoFunction('PEM_read_bio_ECPKParameters');
  FuncLoadError := not assigned(PEM_read_bio_ECPKParameters);
  if FuncLoadError then
  begin
    PEM_read_bio_ECPKParameters :=  @ERROR_PEM_read_bio_ECPKParameters;
  end;

  PEM_write_bio_ECPKParameters := LoadLibCryptoFunction('PEM_write_bio_ECPKParameters');
  FuncLoadError := not assigned(PEM_write_bio_ECPKParameters);
  if FuncLoadError then
  begin
    PEM_write_bio_ECPKParameters :=  @ERROR_PEM_write_bio_ECPKParameters;
  end;

  PEM_read_bio_ECPrivateKey := LoadLibCryptoFunction('PEM_read_bio_ECPrivateKey');
  FuncLoadError := not assigned(PEM_read_bio_ECPrivateKey);
  if FuncLoadError then
  begin
    PEM_read_bio_ECPrivateKey :=  @ERROR_PEM_read_bio_ECPrivateKey;
  end;

  PEM_write_bio_ECPrivateKey := LoadLibCryptoFunction('PEM_write_bio_ECPrivateKey');
  FuncLoadError := not assigned(PEM_write_bio_ECPrivateKey);
  if FuncLoadError then
  begin
    PEM_write_bio_ECPrivateKey :=  @ERROR_PEM_write_bio_ECPrivateKey;
  end;

  PEM_read_bio_EC_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_EC_PUBKEY');
  FuncLoadError := not assigned(PEM_read_bio_EC_PUBKEY);
  if FuncLoadError then
  begin
    PEM_read_bio_EC_PUBKEY :=  @ERROR_PEM_read_bio_EC_PUBKEY;
  end;

  PEM_write_bio_EC_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_EC_PUBKEY');
  FuncLoadError := not assigned(PEM_write_bio_EC_PUBKEY);
  if FuncLoadError then
  begin
    PEM_write_bio_EC_PUBKEY :=  @ERROR_PEM_write_bio_EC_PUBKEY;
  end;

  PEM_read_bio_DHparams := LoadLibCryptoFunction('PEM_read_bio_DHparams');
  FuncLoadError := not assigned(PEM_read_bio_DHparams);
  if FuncLoadError then
  begin
    PEM_read_bio_DHparams :=  @ERROR_PEM_read_bio_DHparams;
  end;

  PEM_write_bio_DHparams := LoadLibCryptoFunction('PEM_write_bio_DHparams');
  FuncLoadError := not assigned(PEM_write_bio_DHparams);
  if FuncLoadError then
  begin
    PEM_write_bio_DHparams :=  @ERROR_PEM_write_bio_DHparams;
  end;

  PEM_write_bio_DHxparams := LoadLibCryptoFunction('PEM_write_bio_DHxparams');
  FuncLoadError := not assigned(PEM_write_bio_DHxparams);
  if FuncLoadError then
  begin
    PEM_write_bio_DHxparams :=  @ERROR_PEM_write_bio_DHxparams;
  end;

  PEM_read_bio_PrivateKey := LoadLibCryptoFunction('PEM_read_bio_PrivateKey');
  FuncLoadError := not assigned(PEM_read_bio_PrivateKey);
  if FuncLoadError then
  begin
    PEM_read_bio_PrivateKey :=  @ERROR_PEM_read_bio_PrivateKey;
  end;

  PEM_write_bio_PrivateKey := LoadLibCryptoFunction('PEM_write_bio_PrivateKey');
  FuncLoadError := not assigned(PEM_write_bio_PrivateKey);
  if FuncLoadError then
  begin
    PEM_write_bio_PrivateKey :=  @ERROR_PEM_write_bio_PrivateKey;
  end;

  PEM_read_bio_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_PUBKEY');
  FuncLoadError := not assigned(PEM_read_bio_PUBKEY);
  if FuncLoadError then
  begin
    PEM_read_bio_PUBKEY :=  @ERROR_PEM_read_bio_PUBKEY;
  end;

  PEM_write_bio_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_PUBKEY');
  FuncLoadError := not assigned(PEM_write_bio_PUBKEY);
  if FuncLoadError then
  begin
    PEM_write_bio_PUBKEY :=  @ERROR_PEM_write_bio_PUBKEY;
  end;

  PEM_write_bio_PrivateKey_traditional := LoadLibCryptoFunction('PEM_write_bio_PrivateKey_traditional');
  FuncLoadError := not assigned(PEM_write_bio_PrivateKey_traditional);
  if FuncLoadError then
  begin
    PEM_write_bio_PrivateKey_traditional :=  @ERROR_PEM_write_bio_PrivateKey_traditional;
  end;

  PEM_write_bio_PKCS8PrivateKey_nid := LoadLibCryptoFunction('PEM_write_bio_PKCS8PrivateKey_nid');
  FuncLoadError := not assigned(PEM_write_bio_PKCS8PrivateKey_nid);
  if FuncLoadError then
  begin
    PEM_write_bio_PKCS8PrivateKey_nid :=  @ERROR_PEM_write_bio_PKCS8PrivateKey_nid;
  end;

  PEM_write_bio_PKCS8PrivateKey := LoadLibCryptoFunction('PEM_write_bio_PKCS8PrivateKey');
  FuncLoadError := not assigned(PEM_write_bio_PKCS8PrivateKey);
  if FuncLoadError then
  begin
    PEM_write_bio_PKCS8PrivateKey :=  @ERROR_PEM_write_bio_PKCS8PrivateKey;
  end;

  i2d_PKCS8PrivateKey_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_bio');
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_bio);
  if FuncLoadError then
  begin
    i2d_PKCS8PrivateKey_bio :=  @ERROR_i2d_PKCS8PrivateKey_bio;
  end;

  i2d_PKCS8PrivateKey_nid_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_nid_bio');
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_nid_bio);
  if FuncLoadError then
  begin
    i2d_PKCS8PrivateKey_nid_bio :=  @ERROR_i2d_PKCS8PrivateKey_nid_bio;
  end;

  d2i_PKCS8PrivateKey_bio := LoadLibCryptoFunction('d2i_PKCS8PrivateKey_bio');
  FuncLoadError := not assigned(d2i_PKCS8PrivateKey_bio);
  if FuncLoadError then
  begin
    d2i_PKCS8PrivateKey_bio :=  @ERROR_d2i_PKCS8PrivateKey_bio;
  end;

  PEM_read_bio_Parameters := LoadLibCryptoFunction('PEM_read_bio_Parameters');
  FuncLoadError := not assigned(PEM_read_bio_Parameters);
  if FuncLoadError then
  begin
    PEM_read_bio_Parameters :=  @ERROR_PEM_read_bio_Parameters;
  end;

  PEM_write_bio_Parameters := LoadLibCryptoFunction('PEM_write_bio_Parameters');
  FuncLoadError := not assigned(PEM_write_bio_Parameters);
  if FuncLoadError then
  begin
    PEM_write_bio_Parameters :=  @ERROR_PEM_write_bio_Parameters;
  end;

  b2i_PrivateKey := LoadLibCryptoFunction('b2i_PrivateKey');
  FuncLoadError := not assigned(b2i_PrivateKey);
  if FuncLoadError then
  begin
    b2i_PrivateKey :=  @ERROR_b2i_PrivateKey;
  end;

  b2i_PublicKey := LoadLibCryptoFunction('b2i_PublicKey');
  FuncLoadError := not assigned(b2i_PublicKey);
  if FuncLoadError then
  begin
    b2i_PublicKey :=  @ERROR_b2i_PublicKey;
  end;

  b2i_PrivateKey_bio := LoadLibCryptoFunction('b2i_PrivateKey_bio');
  FuncLoadError := not assigned(b2i_PrivateKey_bio);
  if FuncLoadError then
  begin
    b2i_PrivateKey_bio :=  @ERROR_b2i_PrivateKey_bio;
  end;

  b2i_PublicKey_bio := LoadLibCryptoFunction('b2i_PublicKey_bio');
  FuncLoadError := not assigned(b2i_PublicKey_bio);
  if FuncLoadError then
  begin
    b2i_PublicKey_bio :=  @ERROR_b2i_PublicKey_bio;
  end;

  i2b_PrivateKey_bio := LoadLibCryptoFunction('i2b_PrivateKey_bio');
  FuncLoadError := not assigned(i2b_PrivateKey_bio);
  if FuncLoadError then
  begin
    i2b_PrivateKey_bio :=  @ERROR_i2b_PrivateKey_bio;
  end;

  i2b_PublicKey_bio := LoadLibCryptoFunction('i2b_PublicKey_bio');
  FuncLoadError := not assigned(i2b_PublicKey_bio);
  if FuncLoadError then
  begin
    i2b_PublicKey_bio :=  @ERROR_i2b_PublicKey_bio;
  end;

  b2i_PVK_bio := LoadLibCryptoFunction('b2i_PVK_bio');
  FuncLoadError := not assigned(b2i_PVK_bio);
  if FuncLoadError then
  begin
    b2i_PVK_bio :=  @ERROR_b2i_PVK_bio;
  end;

  i2b_PVK_bio := LoadLibCryptoFunction('i2b_PVK_bio');
  FuncLoadError := not assigned(i2b_PVK_bio);
  if FuncLoadError then
  begin
    i2b_PVK_bio :=  @ERROR_i2b_PVK_bio;
  end;

end;

procedure UnLoad;
begin
  PEM_get_EVP_CIPHER_INFO := nil;
  PEM_do_header := nil;
  PEM_read_bio := nil;
  PEM_read_bio_ex := nil;
  PEM_bytes_read_bio_secmem := nil;
  PEM_write_bio := nil;
  PEM_bytes_read_bio := nil;
  PEM_ASN1_read_bio := nil;
  PEM_ASN1_write_bio := nil;
  PEM_X509_INFO_read_bio := nil;
  PEM_X509_INFO_write_bio := nil;
  PEM_SignInit := nil;
  PEM_SignUpdate := nil;
  PEM_SignFinal := nil;
  PEM_def_callback := nil;
  PEM_proc_type := nil;
  PEM_dek_info := nil;
  PEM_read_bio_X509 := nil;
  PEM_write_bio_X509 := nil;
  PEM_read_bio_X509_AUX := nil;
  PEM_write_bio_X509_AUX := nil;
  PEM_read_bio_X509_REQ := nil;
  PEM_write_bio_X509_REQ := nil;
  PEM_write_bio_X509_REQ_NEW := nil;
  PEM_read_bio_X509_CRL := nil;
  PEM_write_bio_X509_CRL := nil;
  PEM_read_bio_PKCS7 := nil;
  PEM_write_bio_PKCS7 := nil;
  PEM_read_bio_PKCS8 := nil;
  PEM_write_bio_PKCS8 := nil;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := nil;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := nil;
  PEM_read_bio_RSAPrivateKey := nil;
  PEM_write_bio_RSAPrivateKey := nil;
  PEM_read_bio_RSAPublicKey := nil;
  PEM_write_bio_RSAPublicKey := nil;
  PEM_read_bio_RSA_PUBKEY := nil;
  PEM_write_bio_RSA_PUBKEY := nil;
  PEM_read_bio_DSAPrivateKey := nil;
  PEM_write_bio_DSAPrivateKey := nil;
  PEM_read_bio_DSA_PUBKEY := nil;
  PEM_write_bio_DSA_PUBKEY := nil;
  PEM_read_bio_DSAparams := nil;
  PEM_write_bio_DSAparams := nil;
  PEM_read_bio_ECPKParameters := nil;
  PEM_write_bio_ECPKParameters := nil;
  PEM_read_bio_ECPrivateKey := nil;
  PEM_write_bio_ECPrivateKey := nil;
  PEM_read_bio_EC_PUBKEY := nil;
  PEM_write_bio_EC_PUBKEY := nil;
  PEM_read_bio_DHparams := nil;
  PEM_write_bio_DHparams := nil;
  PEM_write_bio_DHxparams := nil;
  PEM_read_bio_PrivateKey := nil;
  PEM_write_bio_PrivateKey := nil;
  PEM_read_bio_PUBKEY := nil;
  PEM_write_bio_PUBKEY := nil;
  PEM_write_bio_PrivateKey_traditional := nil;
  PEM_write_bio_PKCS8PrivateKey_nid := nil;
  PEM_write_bio_PKCS8PrivateKey := nil;
  i2d_PKCS8PrivateKey_bio := nil;
  i2d_PKCS8PrivateKey_nid_bio := nil;
  d2i_PKCS8PrivateKey_bio := nil;
  PEM_read_bio_Parameters := nil;
  PEM_write_bio_Parameters := nil;
  b2i_PrivateKey := nil;
  b2i_PublicKey := nil;
  b2i_PrivateKey_bio := nil;
  b2i_PublicKey_bio := nil;
  i2b_PrivateKey_bio := nil;
  i2b_PublicKey_bio := nil;
  b2i_PVK_bio := nil;
  i2b_PVK_bio := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
