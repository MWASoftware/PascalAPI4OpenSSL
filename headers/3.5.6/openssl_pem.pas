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

unit openssl_pem;

{
  Generated from OpenSSL 3.5.6 Header File pem.h - Tue 19 May 14:28:05 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_pem.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_pkcs7,openssl_asn1,openssl_ec,
     openssl_e_os2,openssl_bio,openssl_safestack,openssl_evp,openssl_x509,
     openssl_pemerr,openssl_symhacks;


{* Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_PEM_H}
  {$define OPENSSL_PEM_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_PEM_H}
  {$endif}
  {$ifndef  OPENSSL_NO_STDIO}
  {$endif}

const
  PEM_BUFSIZE = 1024;
  PEM_STRING_X509_OLD = 'X509 CERTIFICATE';
  PEM_STRING_X509 = 'CERTIFICATE';
  PEM_STRING_X509_TRUSTED = 'TRUSTED CERTIFICATE';
  PEM_STRING_X509_REQ_OLD = 'NEW CERTIFICATE REQUEST';
  PEM_STRING_X509_REQ = 'CERTIFICATE REQUEST';
  PEM_STRING_X509_CRL = 'X509 CRL';
  PEM_STRING_EVP_PKEY = 'ANY PRIVATE KEY';
  PEM_STRING_PUBLIC = 'PUBLIC KEY';
  PEM_STRING_RSA = 'RSA PRIVATE KEY';
  PEM_STRING_RSA_PUBLIC = 'RSA PUBLIC KEY';
  PEM_STRING_DSA = 'DSA PRIVATE KEY';
  PEM_STRING_DSA_PUBLIC = 'DSA PUBLIC KEY';
  PEM_STRING_PKCS7 = 'PKCS7';
  PEM_STRING_PKCS7_SIGNED = 'PKCS #7 SIGNED DATA';
  PEM_STRING_PKCS8 = 'ENCRYPTED PRIVATE KEY';
  PEM_STRING_PKCS8INF = 'PRIVATE KEY';
  PEM_STRING_DHPARAMS = 'DH PARAMETERS';
  PEM_STRING_DHXPARAMS = 'X9.42 DH PARAMETERS';
  PEM_STRING_SSL_SESSION = 'SSL SESSION PARAMETERS';
  PEM_STRING_DSAPARAMS = 'DSA PARAMETERS';
  PEM_STRING_ECDSA_PUBLIC = 'ECDSA PUBLIC KEY';
  PEM_STRING_ECPARAMETERS = 'EC PARAMETERS';
  PEM_STRING_ECPRIVATEKEY = 'EC PRIVATE KEY';
  PEM_STRING_PARAMETERS = 'PARAMETERS';
  PEM_STRING_CMS = 'CMS';
  PEM_STRING_SM2PRIVATEKEY = 'SM2 PRIVATE KEY';
  PEM_STRING_SM2PARAMETERS = 'SM2 PARAMETERS';
  PEM_STRING_ACERT = 'ATTRIBUTE CERTIFICATE';
  PEM_TYPE_ENCRYPTED = 10;
  PEM_TYPE_MIC_ONLY = 20;
  PEM_TYPE_MIC_CLEAR = 30;
  PEM_TYPE_CLEAR = 40;
  {# define  PEM_read_cb_fnsig(name,type,INTYPE,readname) type *PEM_ ##readname ##_ ##name(INTYPE *out, type **x, pem_password_cb 
*cb, void *u)}
  {# define  PEM_read_cb_ex_fnsig(name,type,INTYPE,readname) type *PEM_ ##readname ##_ ##name ##_ex(INTYPE *out, type **x, pem_password_cb 
*cb, void *u, OSSL_LIB_CTX *libctx, const char *propq)}
  {# define  PEM_write_fnsig(name,type,OUTTYPE,writename) int PEM_ ##writename ##_ ##name(OUTTYPE *out, const type *x)}
  {# define  PEM_write_cb_fnsig(name,type,OUTTYPE,writename) int PEM_ ##writename ##_ ##name(OUTTYPE *out, const type *x, const EVP_CIPHER 
*enc, const unsigned char *kstr, int klen, pem_password_cb *cb, void *u)}
  {# define  PEM_write_ex_fnsig(name,type,OUTTYPE,writename) int PEM_ ##writename ##_ ##name ##_ex(OUTTYPE *out, const type *x, OSSL_LIB_CTX 
*libctx, const char *propq)}
  {# define  PEM_write_cb_ex_fnsig(name,type,OUTTYPE,writename) int PEM_ ##writename ##_ ##name ##_ex(OUTTYPE *out, const type *x,
 const EVP_CIPHER *enc, const unsigned char *kstr, int klen, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx, const char *propq)}
  
  {* These macros make the PEM_read/PEM_write functions easier to maintain and
  * write. Now they are all implemented with either: IMPLEMENT_PEM_rw(...) or
  * IMPLEMENT_PEM_rw_cb(...)
  }
  {$ifdef OPENSSL_NO_STDIO}
{# define  IMPLEMENT_PEM_read_fp(name,type,str,asn1)}
{# define  IMPLEMENT_PEM_write_fp(name,type,str,asn1)}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_fp_const(name,type,str,asn1)}
    {$endif}
{# define  IMPLEMENT_PEM_write_cb_fp(name,type,str,asn1)}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_cb_fp_const(name,type,str,asn1)}
    {$endif}
  {$else}
(*# define  IMPLEMENT_PEM_read_fp(name,type,str,asn1) type *PEM_read_ ##name(FILE *fp, type **x, pem_password_cb *cb, void *u) { 
return PEM_ASN1_read((d2i_of_void * )d2i_ ##asn1, str, fp, (void ** )x, cb, u); }*)
(*# define  IMPLEMENT_PEM_write_fp(name,type,str,asn1) PEM_write_fnsig(name, type, FILE, write) { return PEM_ASN1_write((i2d_of_void 
* )i2d_ ##asn1, str, out, x, NULL, NULL, 0, NULL, NULL); }*)
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_fp_const(name,type,str,asn1) IMPLEMENT_PEM_write_fp(name, type, str, asn1)} { Blacklisted Macro}
    {$endif}
(*# define  IMPLEMENT_PEM_write_cb_fp(name,type,str,asn1) PEM_write_cb_fnsig(name, type, FILE, write) { return PEM_ASN1_write((i2d_of_void 
* )i2d_ ##asn1, str, out, x, enc, kstr, klen, cb, u); }*)
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_cb_fp_const(name,type,str,asn1) IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)} { Blacklisted Macro}
    {$endif}
  {$endif}
(*# define  IMPLEMENT_PEM_read_bio(name,type,str,asn1) type *PEM_read_bio_ ##name(BIO *bp, type **x, pem_password_cb *cb, void *u) 
{ return PEM_ASN1_read_bio((d2i_of_void * )d2i_ ##asn1, str, bp, (void ** )x, cb, u); }*)
(*# define  IMPLEMENT_PEM_write_bio(name,type,str,asn1) PEM_write_fnsig(name, type, BIO, write_bio) { return PEM_ASN1_write_bio((i2d_of_void 
* )i2d_ ##asn1, str, out, x, NULL, NULL, 0, NULL, NULL); }*)
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_bio_const(name,type,str,asn1) IMPLEMENT_PEM_write_bio(name, type, str, asn1)} { Blacklisted Macro}
  {$endif}
(*# define  IMPLEMENT_PEM_write_cb_bio(name,type,str,asn1) PEM_write_cb_fnsig(name, type, BIO, write_bio) { return PEM_ASN1_write_bio((i2d_of_void 
* )i2d_ ##asn1, str, out, x, enc, kstr, klen, cb, u); }*)
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_cb_bio_const(name,type,str,asn1) IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)} { Blacklisted Macro}
  {$endif}
{# define  IMPLEMENT_PEM_write(name,type,str,asn1) IMPLEMENT_PEM_write_bio(name, type, str, asn1) IMPLEMENT_PEM_write_fp(name, type,
 str, asn1)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_const(name,type,str,asn1) IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) IMPLEMENT_PEM_write_fp_const(name,
 type, str, asn1)}
  {$endif}
{# define  IMPLEMENT_PEM_write_cb(name,type,str,asn1) IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) IMPLEMENT_PEM_write_cb_fp(name,
 type, str, asn1)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_write_cb_const(name,type,str,asn1) IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) IMPLEMENT_PEM_write_cb_fp_const(name,
 type, str, asn1)}
  {$endif}
{# define  IMPLEMENT_PEM_read(name,type,str,asn1) IMPLEMENT_PEM_read_bio(name, type, str, asn1) IMPLEMENT_PEM_read_fp(name, type,
 str, asn1)}
{# define  IMPLEMENT_PEM_rw(name,type,str,asn1) IMPLEMENT_PEM_read(name, type, str, asn1) IMPLEMENT_PEM_write(name, type, str, asn1)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  IMPLEMENT_PEM_rw_const(name,type,str,asn1) IMPLEMENT_PEM_read(name, type, str, asn1) IMPLEMENT_PEM_write_const(name, 
type, str, asn1)}
  {$endif}
{# define  IMPLEMENT_PEM_rw_cb(name,type,str,asn1) IMPLEMENT_PEM_read(name, type, str, asn1) IMPLEMENT_PEM_write_cb(name, type, 
str, asn1)}
  { These are the same except they are for the declarations }
  
  {* The mysterious 'extern' that's passed to some macros is innocuous,
  * and is there to quiet pre-C99 compilers that may complain about empty
  * arguments in macro calls.
  }
  {$if  defined(OPENSSL_NO_STDIO)}
{# define  DECLARE_PEM_read_fp_attr(attr,name,type)}
{# define  DECLARE_PEM_read_fp_ex_attr(attr,name,type)}
{# define  DECLARE_PEM_write_fp_attr(attr,name,type)}
{# define  DECLARE_PEM_write_fp_ex_attr(attr,name,type)}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  DECLARE_PEM_write_fp_const_attr(attr,name,type)}
    {$endif}
{# define  DECLARE_PEM_write_cb_fp_attr(attr,name,type)}
{# define  DECLARE_PEM_write_cb_fp_ex_attr(attr,name,type)}
  {$else}
{# define  DECLARE_PEM_read_fp_attr(attr,name,type) attr PEM_read_cb_fnsig(name, type, FILE, read);}
{# define  DECLARE_PEM_read_fp_ex_attr(attr,name,type) attr PEM_read_cb_fnsig(name, type, FILE, read); attr PEM_read_cb_ex_fnsig(name,
 type, FILE, read);}
{# define  DECLARE_PEM_write_fp_attr(attr,name,type) attr PEM_write_fnsig(name, type, FILE, write);}
{# define  DECLARE_PEM_write_fp_ex_attr(attr,name,type) attr PEM_write_fnsig(name, type, FILE, write); attr PEM_write_ex_fnsig(name,
 type, FILE, write);}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  DECLARE_PEM_write_fp_const_attr(attr,name,type) attr PEM_write_fnsig(name, type, FILE, write);}
    {$endif}
{# define  DECLARE_PEM_write_cb_fp_attr(attr,name,type) attr PEM_write_cb_fnsig(name, type, FILE, write);}
{# define  DECLARE_PEM_write_cb_fp_ex_attr(attr,name,type) attr PEM_write_cb_fnsig(name, type, FILE, write); attr PEM_write_cb_ex_fnsig(name,
 type, FILE, write);}
  {$endif}
{# define  DECLARE_PEM_read_fp(name,type) DECLARE_PEM_read_fp_attr(extern, name, type)}
{# define  DECLARE_PEM_write_fp(name,type) DECLARE_PEM_write_fp_attr(extern, name, type)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  DECLARE_PEM_write_fp_const(name,type) DECLARE_PEM_write_fp_const_attr(extern, name, type)}
  {$endif}
{# define  DECLARE_PEM_write_cb_fp(name,type) DECLARE_PEM_write_cb_fp_attr(extern, name, type)}
{# define  DECLARE_PEM_read_bio_attr(attr,name,type) attr PEM_read_cb_fnsig(name, type, BIO, read_bio);}
{# define  DECLARE_PEM_read_bio_ex_attr(attr,name,type) attr PEM_read_cb_fnsig(name, type, BIO, read_bio); attr PEM_read_cb_ex_fnsig(name,
 type, BIO, read_bio);}
{# define  DECLARE_PEM_read_bio(name,type) DECLARE_PEM_read_bio_attr(extern, name, type)}
{# define  DECLARE_PEM_read_bio_ex(name,type) DECLARE_PEM_read_bio_ex_attr(extern, name, type)}
{# define  DECLARE_PEM_write_bio_attr(attr,name,type) attr PEM_write_fnsig(name, type, BIO, write_bio);}
{# define  DECLARE_PEM_write_bio_ex_attr(attr,name,type) attr PEM_write_fnsig(name, type, BIO, write_bio); attr PEM_write_ex_fnsig(name,
 type, BIO, write_bio);}
{# define  DECLARE_PEM_write_bio(name,type) DECLARE_PEM_write_bio_attr(extern, name, type)}
{# define  DECLARE_PEM_write_bio_ex(name,type) DECLARE_PEM_write_bio_ex_attr(extern, name, type)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  DECLARE_PEM_write_bio_const_attr(attr,name,type) attr PEM_write_fnsig(name, type, BIO, write_bio);}
{# define  DECLARE_PEM_write_bio_const(name,type) DECLARE_PEM_write_bio_const_attr(extern, name, type)}
  {$endif}
{# define  DECLARE_PEM_write_cb_bio_attr(attr,name,type) attr PEM_write_cb_fnsig(name, type, BIO, write_bio);}
{# define  DECLARE_PEM_write_cb_bio_ex_attr(attr,name,type) attr PEM_write_cb_fnsig(name, type, BIO, write_bio); attr PEM_write_cb_ex_fnsig(name,
 type, BIO, write_bio);}
{# define  DECLARE_PEM_write_cb_bio(name,type) DECLARE_PEM_write_cb_bio_attr(extern, name, type)}
{# define  DECLARE_PEM_write_cb_ex_bio(name,type) DECLARE_PEM_write_cb_bio_ex_attr(extern, name, type)}
{# define  DECLARE_PEM_write_attr(attr,name,type) DECLARE_PEM_write_bio_attr(attr, name, type) DECLARE_PEM_write_fp_attr(attr, name,
 type)}
{# define  DECLARE_PEM_write_ex_attr(attr,name,type) DECLARE_PEM_write_bio_ex_attr(attr, name, type) DECLARE_PEM_write_fp_ex_attr(attr,
 name, type)}
{# define  DECLARE_PEM_write(name,type) DECLARE_PEM_write_attr(extern, name, type)}
{# define  DECLARE_PEM_write_ex(name,type) DECLARE_PEM_write_ex_attr(extern, name, type)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  DECLARE_PEM_write_const_attr(attr,name,type) DECLARE_PEM_write_bio_const_attr(attr, name, type) DECLARE_PEM_write_fp_const_attr(attr,
 name, type)}
{# define  DECLARE_PEM_write_const(name,type) DECLARE_PEM_write_const_attr(extern, name, type)}
  {$endif}
{# define  DECLARE_PEM_write_cb_attr(attr,name,type) DECLARE_PEM_write_cb_bio_attr(attr, name, type) DECLARE_PEM_write_cb_fp_attr(attr,
 name, type)}
{# define  DECLARE_PEM_write_cb_ex_attr(attr,name,type) DECLARE_PEM_write_cb_bio_ex_attr(attr, name, type) DECLARE_PEM_write_cb_fp_ex_attr(attr,
 name, type)}
{# define  DECLARE_PEM_write_cb(name,type) DECLARE_PEM_write_cb_attr(extern, name, type)}
{# define  DECLARE_PEM_write_cb_ex(name,type) DECLARE_PEM_write_cb_ex_attr(extern, name, type)}
{# define  DECLARE_PEM_read_attr(attr,name,type) DECLARE_PEM_read_bio_attr(attr, name, type) DECLARE_PEM_read_fp_attr(attr, name,
 type)}
{# define  DECLARE_PEM_read_ex_attr(attr,name,type) DECLARE_PEM_read_bio_ex_attr(attr, name, type) DECLARE_PEM_read_fp_ex_attr(attr,
 name, type)}
{# define  DECLARE_PEM_read(name,type) DECLARE_PEM_read_attr(extern, name, type)}
{# define  DECLARE_PEM_read_ex(name,type) DECLARE_PEM_read_ex_attr(extern, name, type)}
{# define  DECLARE_PEM_rw_attr(attr,name,type) DECLARE_PEM_read_attr(attr, name, type) DECLARE_PEM_write_attr(attr, name, type)}
{# define  DECLARE_PEM_rw_ex_attr(attr,name,type) DECLARE_PEM_read_ex_attr(attr, name, type) DECLARE_PEM_write_ex_attr(attr, name,
 type)}
{# define  DECLARE_PEM_rw(name,type) DECLARE_PEM_rw_attr(extern, name, type)}
{# define  DECLARE_PEM_rw_ex(name,type) DECLARE_PEM_rw_ex_attr(extern, name, type)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  DECLARE_PEM_rw_const_attr(attr,name,type) DECLARE_PEM_read_attr(attr, name, type) DECLARE_PEM_write_const_attr(attr, 
name, type)}
{# define  DECLARE_PEM_rw_const(name,type) DECLARE_PEM_rw_const_attr(extern, name, type)}
  {$endif}
{# define  DECLARE_PEM_rw_cb_attr(attr,name,type) DECLARE_PEM_read_attr(attr, name, type) DECLARE_PEM_write_cb_attr(attr, name, 
type)}
{# define  DECLARE_PEM_rw_cb_ex_attr(attr,name,type) DECLARE_PEM_read_ex_attr(attr, name, type) DECLARE_PEM_write_cb_ex_attr(attr,
 name, type)}
{# define  DECLARE_PEM_rw_cb(name,type) DECLARE_PEM_rw_cb_attr(extern, name, type)}
{# define  DECLARE_PEM_rw_cb_ex(name,type) DECLARE_PEM_rw_cb_ex_attr(extern, name, type)}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_get_EVP_CIPHER_INFO';
  function PEM_do_header(cipher: PEVP_CIPHER_INFO; data: Pbyte; len: POpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_do_header';
  function PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_read_bio';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM PEM_get_EVP_CIPHER_INFO}
  {$EXTERNALSYM PEM_do_header}
  {$EXTERNALSYM PEM_read_bio}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl;
  function Load_PEM_do_header(cipher: PEVP_CIPHER_INFO; data: Pbyte; len: POpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  PEM_get_EVP_CIPHER_INFO: function(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl = Load_PEM_get_EVP_CIPHER_INFO;
  PEM_do_header: function(cipher: PEVP_CIPHER_INFO; data: Pbyte; len: POpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_do_header;
  PEM_read_bio: function(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PEM_read_bio;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  PEM_FLAG_SECURE = $1;
  PEM_FLAG_EAY_COMPATIBLE = $2;
  PEM_FLAG_ONLY_B64 = $4;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_read_bio_ex';
  function PEM_bytes_read_bio_secmem(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_bytes_read_bio_secmem';
  function PEM_write_bio(bp: PBIO; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio';
  function PEM_bytes_read_bio(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_bytes_read_bio';
  function PEM_ASN1_read_bio(d2i: Pd2i_of_void; name: PAnsiChar; bp: PBIO; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl; external CLibCrypto name 'PEM_ASN1_read_bio';
  function PEM_ASN1_write_bio(i2d: Pi2d_of_void; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_ASN1_write_bio';
  function PEM_ASN1_write_bio_ctx(i2d: POSSL_i2d_of_void_ctx; vctx: pointer; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_ASN1_write_bio_ctx';
  function PEM_X509_INFO_read_bio(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl; external CLibCrypto name 'PEM_X509_INFO_read_bio';
  function PEM_X509_INFO_read_bio_ex(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl; external CLibCrypto name 'PEM_X509_INFO_read_bio_ex';
  function PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_X509_INFO_write_bio';
  {$else}
  {$EXTERNALSYM PEM_read_bio_ex}
  {$EXTERNALSYM PEM_bytes_read_bio_secmem}
  {$EXTERNALSYM PEM_write_bio}
  {$EXTERNALSYM PEM_bytes_read_bio}
  {$EXTERNALSYM PEM_ASN1_read_bio}
  {$EXTERNALSYM PEM_ASN1_write_bio}
  {$EXTERNALSYM PEM_ASN1_write_bio_ctx}
  {$EXTERNALSYM PEM_X509_INFO_read_bio}
  {$EXTERNALSYM PEM_X509_INFO_read_bio_ex}
  {$EXTERNALSYM PEM_X509_INFO_write_bio}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_PEM_bytes_read_bio_secmem(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio(bp: PBIO; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_PEM_bytes_read_bio(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_ASN1_read_bio(d2i: Pd2i_of_void; name: PAnsiChar; bp: PBIO; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl;
  function Load_PEM_ASN1_write_bio(i2d: Pi2d_of_void; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_ASN1_write_bio_ctx(i2d: POSSL_i2d_of_void_ctx; vctx: pointer; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_X509_INFO_read_bio(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl;
  function Load_PEM_X509_INFO_read_bio_ex(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl;
  function Load_PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;

var
  PEM_read_bio_ex: function(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_PEM_read_bio_ex;
  PEM_bytes_read_bio_secmem: function(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_bytes_read_bio_secmem;
  PEM_write_bio: function(bp: PBIO; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio;
  PEM_bytes_read_bio: function(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_bytes_read_bio;
  PEM_ASN1_read_bio: function(d2i: Pd2i_of_void; name: PAnsiChar; bp: PBIO; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl = Load_PEM_ASN1_read_bio;
  PEM_ASN1_write_bio: function(i2d: Pi2d_of_void; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_ASN1_write_bio;
  PEM_ASN1_write_bio_ctx: function(i2d: POSSL_i2d_of_void_ctx; vctx: pointer; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_ASN1_write_bio_ctx;
  PEM_X509_INFO_read_bio: function(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl = Load_PEM_X509_INFO_read_bio;
  PEM_X509_INFO_read_bio_ex: function(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl = Load_PEM_X509_INFO_read_bio_ex;
  PEM_X509_INFO_write_bio: function(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_X509_INFO_write_bio;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_STDIO}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read(fp: PFILE; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_read';
  function PEM_write(fp: PFILE; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write';
  function PEM_ASN1_read(d2i: Pd2i_of_void; name: PAnsiChar; fp: PFILE; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl; external CLibCrypto name 'PEM_ASN1_read';
  function PEM_ASN1_write(i2d: Pi2d_of_void; name: PAnsiChar; fp: PFILE; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_ASN1_write';
  function PEM_X509_INFO_read(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl; external CLibCrypto name 'PEM_X509_INFO_read';
  function PEM_X509_INFO_read_ex(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl; external CLibCrypto name 'PEM_X509_INFO_read_ex';
    {$else}
  {$EXTERNALSYM PEM_read}
  {$EXTERNALSYM PEM_write}
  {$EXTERNALSYM PEM_ASN1_read}
  {$EXTERNALSYM PEM_ASN1_write}
  {$EXTERNALSYM PEM_X509_INFO_read}
  {$EXTERNALSYM PEM_X509_INFO_read_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read(fp: PFILE; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write(fp: PFILE; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_PEM_ASN1_read(d2i: Pd2i_of_void; name: PAnsiChar; fp: PFILE; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl;
  function Load_PEM_ASN1_write(i2d: Pi2d_of_void; name: PAnsiChar; fp: PFILE; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_X509_INFO_read(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl;
  function Load_PEM_X509_INFO_read_ex(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl;

var
  PEM_read: function(fp: PFILE; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PEM_read;
  PEM_write: function(fp: PFILE; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PEM_write;
  PEM_ASN1_read: function(d2i: Pd2i_of_void; name: PAnsiChar; fp: PFILE; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl = Load_PEM_ASN1_read;
  PEM_ASN1_write: function(i2d: Pi2d_of_void; name: PAnsiChar; fp: PFILE; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_ASN1_write;
  PEM_X509_INFO_read: function(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl = Load_PEM_X509_INFO_read;
  PEM_X509_INFO_read_ex: function(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl = Load_PEM_X509_INFO_read_ex;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_SignInit';
  function PEM_SignUpdate(ctx: PEVP_MD_CTX; d: Pbyte; cnt: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_SignUpdate';
  function PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_SignFinal';
  { The default pem_password_cb that's used internally }
  function PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_def_callback';
  procedure PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'PEM_proc_type';
  procedure PEM_dek_info(buf: PAnsiChar; type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl; external CLibCrypto name 'PEM_dek_info';
  function PEM_read_bio_X509(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl; external CLibCrypto name 'PEM_read_bio_X509';
  function PEM_read_X509(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl; external CLibCrypto name 'PEM_read_X509';
  function PEM_write_bio_X509(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_X509';
  function PEM_write_X509(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_X509';
  function PEM_read_bio_X509_AUX(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl; external CLibCrypto name 'PEM_read_bio_X509_AUX';
  function PEM_read_X509_AUX(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl; external CLibCrypto name 'PEM_read_X509_AUX';
  function PEM_write_bio_X509_AUX(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_X509_AUX';
  function PEM_write_X509_AUX(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_X509_AUX';
  function PEM_read_bio_X509_REQ(out_: PBIO; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl; external CLibCrypto name 'PEM_read_bio_X509_REQ';
  function PEM_read_X509_REQ(out_: PFILE; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl; external CLibCrypto name 'PEM_read_X509_REQ';
  function PEM_write_bio_X509_REQ(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_X509_REQ';
  function PEM_write_X509_REQ(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_X509_REQ';
  function PEM_write_bio_X509_REQ_NEW(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_X509_REQ_NEW';
  function PEM_write_X509_REQ_NEW(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_X509_REQ_NEW';
  function PEM_read_bio_X509_CRL(out_: PBIO; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl; external CLibCrypto name 'PEM_read_bio_X509_CRL';
  function PEM_read_X509_CRL(out_: PFILE; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl; external CLibCrypto name 'PEM_read_X509_CRL';
  function PEM_write_bio_X509_CRL(out_: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_X509_CRL';
  function PEM_write_X509_CRL(out_: PFILE; x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_X509_CRL';
  function PEM_read_bio_X509_PUBKEY(out_: PBIO; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl; external CLibCrypto name 'PEM_read_bio_X509_PUBKEY';
  function PEM_read_X509_PUBKEY(out_: PFILE; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl; external CLibCrypto name 'PEM_read_X509_PUBKEY';
  function PEM_write_bio_X509_PUBKEY(out_: PBIO; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_X509_PUBKEY';
  function PEM_write_X509_PUBKEY(out_: PFILE; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_X509_PUBKEY';
  function PEM_read_bio_PKCS7(out_: PBIO; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl; external CLibCrypto name 'PEM_read_bio_PKCS7';
  function PEM_read_PKCS7(out_: PFILE; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl; external CLibCrypto name 'PEM_read_PKCS7';
  function PEM_write_bio_PKCS7(out_: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PKCS7';
  function PEM_write_PKCS7(out_: PFILE; x: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PKCS7';
  function PEM_read_bio_NETSCAPE_CERT_SEQUENCE(out_: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl; external CLibCrypto name 'PEM_read_bio_NETSCAPE_CERT_SEQUENCE';
  function PEM_read_NETSCAPE_CERT_SEQUENCE(out_: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl; external CLibCrypto name 'PEM_read_NETSCAPE_CERT_SEQUENCE';
  function PEM_write_bio_NETSCAPE_CERT_SEQUENCE(out_: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_NETSCAPE_CERT_SEQUENCE';
  function PEM_write_NETSCAPE_CERT_SEQUENCE(out_: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_NETSCAPE_CERT_SEQUENCE';
  function PEM_read_bio_PKCS8(out_: PBIO; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl; external CLibCrypto name 'PEM_read_bio_PKCS8';
  function PEM_read_PKCS8(out_: PFILE; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl; external CLibCrypto name 'PEM_read_PKCS8';
  function PEM_write_bio_PKCS8(out_: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PKCS8';
  function PEM_write_PKCS8(out_: PFILE; x: PX509_SIG): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PKCS8';
  function PEM_read_bio_PKCS8_PRIV_KEY_INFO(out_: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto name 'PEM_read_bio_PKCS8_PRIV_KEY_INFO';
  function PEM_read_PKCS8_PRIV_KEY_INFO(out_: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto name 'PEM_read_PKCS8_PRIV_KEY_INFO';
  function PEM_write_bio_PKCS8_PRIV_KEY_INFO(out_: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PKCS8_PRIV_KEY_INFO';
  function PEM_write_PKCS8_PRIV_KEY_INFO(out_: PFILE; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PKCS8_PRIV_KEY_INFO';
  {$else}
  {$EXTERNALSYM PEM_SignInit}
  {$EXTERNALSYM PEM_SignUpdate}
  {$EXTERNALSYM PEM_SignFinal}
  {$EXTERNALSYM PEM_def_callback}
  {$EXTERNALSYM PEM_proc_type}
  {$EXTERNALSYM PEM_dek_info}
  {$EXTERNALSYM PEM_read_bio_X509}
  {$EXTERNALSYM PEM_read_X509}
  {$EXTERNALSYM PEM_write_bio_X509}
  {$EXTERNALSYM PEM_write_X509}
  {$EXTERNALSYM PEM_read_bio_X509_AUX}
  {$EXTERNALSYM PEM_read_X509_AUX}
  {$EXTERNALSYM PEM_write_bio_X509_AUX}
  {$EXTERNALSYM PEM_write_X509_AUX}
  {$EXTERNALSYM PEM_read_bio_X509_REQ}
  {$EXTERNALSYM PEM_read_X509_REQ}
  {$EXTERNALSYM PEM_write_bio_X509_REQ}
  {$EXTERNALSYM PEM_write_X509_REQ}
  {$EXTERNALSYM PEM_write_bio_X509_REQ_NEW}
  {$EXTERNALSYM PEM_write_X509_REQ_NEW}
  {$EXTERNALSYM PEM_read_bio_X509_CRL}
  {$EXTERNALSYM PEM_read_X509_CRL}
  {$EXTERNALSYM PEM_write_bio_X509_CRL}
  {$EXTERNALSYM PEM_write_X509_CRL}
  {$EXTERNALSYM PEM_read_bio_X509_PUBKEY}
  {$EXTERNALSYM PEM_read_X509_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_X509_PUBKEY}
  {$EXTERNALSYM PEM_write_X509_PUBKEY}
  {$EXTERNALSYM PEM_read_bio_PKCS7}
  {$EXTERNALSYM PEM_read_PKCS7}
  {$EXTERNALSYM PEM_write_bio_PKCS7}
  {$EXTERNALSYM PEM_write_PKCS7}
  {$EXTERNALSYM PEM_read_bio_NETSCAPE_CERT_SEQUENCE}
  {$EXTERNALSYM PEM_read_NETSCAPE_CERT_SEQUENCE}
  {$EXTERNALSYM PEM_write_bio_NETSCAPE_CERT_SEQUENCE}
  {$EXTERNALSYM PEM_write_NETSCAPE_CERT_SEQUENCE}
  {$EXTERNALSYM PEM_read_bio_PKCS8}
  {$EXTERNALSYM PEM_read_PKCS8}
  {$EXTERNALSYM PEM_write_bio_PKCS8}
  {$EXTERNALSYM PEM_write_PKCS8}
  {$EXTERNALSYM PEM_read_bio_PKCS8_PRIV_KEY_INFO}
  {$EXTERNALSYM PEM_read_PKCS8_PRIV_KEY_INFO}
  {$EXTERNALSYM PEM_write_bio_PKCS8_PRIV_KEY_INFO}
  {$EXTERNALSYM PEM_write_PKCS8_PRIV_KEY_INFO}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_PEM_SignUpdate(ctx: PEVP_MD_CTX; d: Pbyte; cnt: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: pointer): TOpenSSL_C_INT; cdecl;
  procedure Load_PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl;
  procedure Load_PEM_dek_info(buf: PAnsiChar; type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl;
  function Load_PEM_read_bio_X509(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
  function Load_PEM_read_X509(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
  function Load_PEM_write_bio_X509(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_X509(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_X509_AUX(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
  function Load_PEM_read_X509_AUX(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
  function Load_PEM_write_bio_X509_AUX(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_X509_AUX(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_X509_REQ(out_: PBIO; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl;
  function Load_PEM_read_X509_REQ(out_: PFILE; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl;
  function Load_PEM_write_bio_X509_REQ(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_X509_REQ(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio_X509_REQ_NEW(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_X509_REQ_NEW(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_X509_CRL(out_: PBIO; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl;
  function Load_PEM_read_X509_CRL(out_: PFILE; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl;
  function Load_PEM_write_bio_X509_CRL(out_: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_X509_CRL(out_: PFILE; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_X509_PUBKEY(out_: PBIO; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl;
  function Load_PEM_read_X509_PUBKEY(out_: PFILE; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl;
  function Load_PEM_write_bio_X509_PUBKEY(out_: PBIO; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_X509_PUBKEY(out_: PFILE; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_PKCS7(out_: PBIO; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl;
  function Load_PEM_read_PKCS7(out_: PFILE; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl;
  function Load_PEM_write_bio_PKCS7(out_: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PKCS7(out_: PFILE; x: PPKCS7): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_NETSCAPE_CERT_SEQUENCE(out_: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl;
  function Load_PEM_read_NETSCAPE_CERT_SEQUENCE(out_: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl;
  function Load_PEM_write_bio_NETSCAPE_CERT_SEQUENCE(out_: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_NETSCAPE_CERT_SEQUENCE(out_: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_PKCS8(out_: PBIO; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl;
  function Load_PEM_read_PKCS8(out_: PFILE; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl;
  function Load_PEM_write_bio_PKCS8(out_: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PKCS8(out_: PFILE; x: PX509_SIG): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO(out_: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
  function Load_PEM_read_PKCS8_PRIV_KEY_INFO(out_: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
  function Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO(out_: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PKCS8_PRIV_KEY_INFO(out_: PFILE; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;

var
  PEM_SignInit: function(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PEM_SignInit;
  PEM_SignUpdate: function(ctx: PEVP_MD_CTX; d: Pbyte; cnt: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_PEM_SignUpdate;
  PEM_SignFinal: function(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_PEM_SignFinal;
  { The default pem_password_cb that's used internally }
  PEM_def_callback: function(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_def_callback;
  PEM_proc_type: procedure(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl = Load_PEM_proc_type;
  PEM_dek_info: procedure(buf: PAnsiChar; type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl = Load_PEM_dek_info;
  PEM_read_bio_X509: function(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl = Load_PEM_read_bio_X509;
  PEM_read_X509: function(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl = Load_PEM_read_X509;
  PEM_write_bio_X509: function(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509;
  PEM_write_X509: function(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl = Load_PEM_write_X509;
  PEM_read_bio_X509_AUX: function(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl = Load_PEM_read_bio_X509_AUX;
  PEM_read_X509_AUX: function(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl = Load_PEM_read_X509_AUX;
  PEM_write_bio_X509_AUX: function(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_AUX;
  PEM_write_X509_AUX: function(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl = Load_PEM_write_X509_AUX;
  PEM_read_bio_X509_REQ: function(out_: PBIO; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl = Load_PEM_read_bio_X509_REQ;
  PEM_read_X509_REQ: function(out_: PFILE; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl = Load_PEM_read_X509_REQ;
  PEM_write_bio_X509_REQ: function(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_REQ;
  PEM_write_X509_REQ: function(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_PEM_write_X509_REQ;
  PEM_write_bio_X509_REQ_NEW: function(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_REQ_NEW;
  PEM_write_X509_REQ_NEW: function(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_PEM_write_X509_REQ_NEW;
  PEM_read_bio_X509_CRL: function(out_: PBIO; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl = Load_PEM_read_bio_X509_CRL;
  PEM_read_X509_CRL: function(out_: PFILE; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl = Load_PEM_read_X509_CRL;
  PEM_write_bio_X509_CRL: function(out_: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_CRL;
  PEM_write_X509_CRL: function(out_: PFILE; x: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_PEM_write_X509_CRL;
  PEM_read_bio_X509_PUBKEY: function(out_: PBIO; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl = Load_PEM_read_bio_X509_PUBKEY;
  PEM_read_X509_PUBKEY: function(out_: PFILE; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl = Load_PEM_read_X509_PUBKEY;
  PEM_write_bio_X509_PUBKEY: function(out_: PBIO; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_PUBKEY;
  PEM_write_X509_PUBKEY: function(out_: PFILE; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_X509_PUBKEY;
  PEM_read_bio_PKCS7: function(out_: PBIO; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl = Load_PEM_read_bio_PKCS7;
  PEM_read_PKCS7: function(out_: PFILE; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl = Load_PEM_read_PKCS7;
  PEM_write_bio_PKCS7: function(out_: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS7;
  PEM_write_PKCS7: function(out_: PFILE; x: PPKCS7): TOpenSSL_C_INT; cdecl = Load_PEM_write_PKCS7;
  PEM_read_bio_NETSCAPE_CERT_SEQUENCE: function(out_: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = Load_PEM_read_bio_NETSCAPE_CERT_SEQUENCE;
  PEM_read_NETSCAPE_CERT_SEQUENCE: function(out_: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = Load_PEM_read_NETSCAPE_CERT_SEQUENCE;
  PEM_write_bio_NETSCAPE_CERT_SEQUENCE: function(out_: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_NETSCAPE_CERT_SEQUENCE;
  PEM_write_NETSCAPE_CERT_SEQUENCE: function(out_: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl = Load_PEM_write_NETSCAPE_CERT_SEQUENCE;
  PEM_read_bio_PKCS8: function(out_: PBIO; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl = Load_PEM_read_bio_PKCS8;
  PEM_read_PKCS8: function(out_: PFILE; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl = Load_PEM_read_PKCS8;
  PEM_write_bio_PKCS8: function(out_: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8;
  PEM_write_PKCS8: function(out_: PFILE; x: PX509_SIG): TOpenSSL_C_INT; cdecl = Load_PEM_write_PKCS8;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO: function(out_: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl = Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
  PEM_read_PKCS8_PRIV_KEY_INFO: function(out_: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl = Load_PEM_read_PKCS8_PRIV_KEY_INFO;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO: function(out_: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
  PEM_write_PKCS8_PRIV_KEY_INFO: function(out_: PFILE; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = Load_PEM_write_PKCS8_PRIV_KEY_INFO;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read_bio_RSAPrivateKey(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl; external CLibCrypto name 'PEM_read_bio_RSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_RSAPrivateKey(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl; external CLibCrypto name 'PEM_read_RSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_RSAPrivateKey(out_: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_RSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_RSAPrivateKey(out_: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_RSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_bio_RSAPublicKey(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl; external CLibCrypto name 'PEM_read_bio_RSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_RSAPublicKey(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl; external CLibCrypto name 'PEM_read_RSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_RSAPublicKey(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_RSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_RSAPublicKey(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_RSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_bio_RSA_PUBKEY(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl; external CLibCrypto name 'PEM_read_bio_RSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_RSA_PUBKEY(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl; external CLibCrypto name 'PEM_read_RSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_RSA_PUBKEY(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_RSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_RSA_PUBKEY(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_RSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM PEM_read_bio_RSAPrivateKey}
  {$EXTERNALSYM PEM_read_RSAPrivateKey}
  {$EXTERNALSYM PEM_write_bio_RSAPrivateKey}
  {$EXTERNALSYM PEM_write_RSAPrivateKey}
  {$EXTERNALSYM PEM_read_bio_RSAPublicKey}
  {$EXTERNALSYM PEM_read_RSAPublicKey}
  {$EXTERNALSYM PEM_write_bio_RSAPublicKey}
  {$EXTERNALSYM PEM_write_RSAPublicKey}
  {$EXTERNALSYM PEM_read_bio_RSA_PUBKEY}
  {$EXTERNALSYM PEM_read_RSA_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_RSA_PUBKEY}
  {$EXTERNALSYM PEM_write_RSA_PUBKEY}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read_bio_RSAPrivateKey(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
  function Load_PEM_read_RSAPrivateKey(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
  function Load_PEM_write_bio_RSAPrivateKey(out_: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_RSAPrivateKey(out_: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_RSAPublicKey(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
  function Load_PEM_read_RSAPublicKey(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
  function Load_PEM_write_bio_RSAPublicKey(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_RSAPublicKey(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_RSA_PUBKEY(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
  function Load_PEM_read_RSA_PUBKEY(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
  function Load_PEM_write_bio_RSA_PUBKEY(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_RSA_PUBKEY(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl;

var
  PEM_read_bio_RSAPrivateKey: function(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl = Load_PEM_read_bio_RSAPrivateKey;
  PEM_read_RSAPrivateKey: function(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl = Load_PEM_read_RSAPrivateKey;
  PEM_write_bio_RSAPrivateKey: function(out_: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_RSAPrivateKey;
  PEM_write_RSAPrivateKey: function(out_: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_RSAPrivateKey;
  PEM_read_bio_RSAPublicKey: function(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl = Load_PEM_read_bio_RSAPublicKey;
  PEM_read_RSAPublicKey: function(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl = Load_PEM_read_RSAPublicKey;
  PEM_write_bio_RSAPublicKey: function(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_RSAPublicKey;
  PEM_write_RSAPublicKey: function(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_RSAPublicKey;
  PEM_read_bio_RSA_PUBKEY: function(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl = Load_PEM_read_bio_RSA_PUBKEY;
  PEM_read_RSA_PUBKEY: function(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl = Load_PEM_read_RSA_PUBKEY;
  PEM_write_bio_RSA_PUBKEY: function(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_RSA_PUBKEY;
  PEM_write_RSA_PUBKEY: function(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_RSA_PUBKEY;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DSA}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read_bio_DSAPrivateKey(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl; external CLibCrypto name 'PEM_read_bio_DSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_DSAPrivateKey(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl; external CLibCrypto name 'PEM_read_DSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_DSAPrivateKey(out_: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_DSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_DSAPrivateKey(out_: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_DSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_bio_DSA_PUBKEY(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl; external CLibCrypto name 'PEM_read_bio_DSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_DSA_PUBKEY(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl; external CLibCrypto name 'PEM_read_DSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_DSA_PUBKEY(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_DSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_DSA_PUBKEY(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_DSA_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_bio_DSAparams(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl; external CLibCrypto name 'PEM_read_bio_DSAparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_DSAparams(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl; external CLibCrypto name 'PEM_read_DSAparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_DSAparams(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_DSAparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_DSAparams(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_DSAparams'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM PEM_read_bio_DSAPrivateKey}
  {$EXTERNALSYM PEM_read_DSAPrivateKey}
  {$EXTERNALSYM PEM_write_bio_DSAPrivateKey}
  {$EXTERNALSYM PEM_write_DSAPrivateKey}
  {$EXTERNALSYM PEM_read_bio_DSA_PUBKEY}
  {$EXTERNALSYM PEM_read_DSA_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_DSA_PUBKEY}
  {$EXTERNALSYM PEM_write_DSA_PUBKEY}
  {$EXTERNALSYM PEM_read_bio_DSAparams}
  {$EXTERNALSYM PEM_read_DSAparams}
  {$EXTERNALSYM PEM_write_bio_DSAparams}
  {$EXTERNALSYM PEM_write_DSAparams}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read_bio_DSAPrivateKey(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
  function Load_PEM_read_DSAPrivateKey(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
  function Load_PEM_write_bio_DSAPrivateKey(out_: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_DSAPrivateKey(out_: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_DSA_PUBKEY(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
  function Load_PEM_read_DSA_PUBKEY(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
  function Load_PEM_write_bio_DSA_PUBKEY(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_DSA_PUBKEY(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_DSAparams(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
  function Load_PEM_read_DSAparams(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
  function Load_PEM_write_bio_DSAparams(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_DSAparams(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl;

var
  PEM_read_bio_DSAPrivateKey: function(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl = Load_PEM_read_bio_DSAPrivateKey;
  PEM_read_DSAPrivateKey: function(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl = Load_PEM_read_DSAPrivateKey;
  PEM_write_bio_DSAPrivateKey: function(out_: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DSAPrivateKey;
  PEM_write_DSAPrivateKey: function(out_: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_DSAPrivateKey;
  PEM_read_bio_DSA_PUBKEY: function(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl = Load_PEM_read_bio_DSA_PUBKEY;
  PEM_read_DSA_PUBKEY: function(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl = Load_PEM_read_DSA_PUBKEY;
  PEM_write_bio_DSA_PUBKEY: function(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DSA_PUBKEY;
  PEM_write_DSA_PUBKEY: function(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_DSA_PUBKEY;
  PEM_read_bio_DSAparams: function(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl = Load_PEM_read_bio_DSAparams;
  PEM_read_DSAparams: function(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl = Load_PEM_read_DSAparams;
  PEM_write_bio_DSAparams: function(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DSAparams;
  PEM_write_DSAparams: function(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_DSAparams;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_EC}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read_bio_ECPKParameters(out_: PBIO; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl; external CLibCrypto name 'PEM_read_bio_ECPKParameters'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_ECPKParameters(out_: PFILE; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl; external CLibCrypto name 'PEM_read_ECPKParameters'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_ECPKParameters(out_: PBIO; x: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_ECPKParameters'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_ECPKParameters(out_: PFILE; x: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_ECPKParameters'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_bio_ECPrivateKey(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl; external CLibCrypto name 'PEM_read_bio_ECPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_ECPrivateKey(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl; external CLibCrypto name 'PEM_read_ECPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_ECPrivateKey(out_: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_ECPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_ECPrivateKey(out_: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_ECPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_bio_EC_PUBKEY(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl; external CLibCrypto name 'PEM_read_bio_EC_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_EC_PUBKEY(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl; external CLibCrypto name 'PEM_read_EC_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_EC_PUBKEY(out_: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_EC_PUBKEY'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_EC_PUBKEY(out_: PFILE; x: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_EC_PUBKEY'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM PEM_read_bio_ECPKParameters}
  {$EXTERNALSYM PEM_read_ECPKParameters}
  {$EXTERNALSYM PEM_write_bio_ECPKParameters}
  {$EXTERNALSYM PEM_write_ECPKParameters}
  {$EXTERNALSYM PEM_read_bio_ECPrivateKey}
  {$EXTERNALSYM PEM_read_ECPrivateKey}
  {$EXTERNALSYM PEM_write_bio_ECPrivateKey}
  {$EXTERNALSYM PEM_write_ECPrivateKey}
  {$EXTERNALSYM PEM_read_bio_EC_PUBKEY}
  {$EXTERNALSYM PEM_read_EC_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_EC_PUBKEY}
  {$EXTERNALSYM PEM_write_EC_PUBKEY}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read_bio_ECPKParameters(out_: PBIO; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl;
  function Load_PEM_read_ECPKParameters(out_: PFILE; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl;
  function Load_PEM_write_bio_ECPKParameters(out_: PBIO; x: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_ECPKParameters(out_: PFILE; x: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_ECPrivateKey(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
  function Load_PEM_read_ECPrivateKey(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
  function Load_PEM_write_bio_ECPrivateKey(out_: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_ECPrivateKey(out_: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_EC_PUBKEY(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
  function Load_PEM_read_EC_PUBKEY(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
  function Load_PEM_write_bio_EC_PUBKEY(out_: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_EC_PUBKEY(out_: PFILE; x: PEC_KEY): TOpenSSL_C_INT; cdecl;

var
  PEM_read_bio_ECPKParameters: function(out_: PBIO; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl = Load_PEM_read_bio_ECPKParameters;
  PEM_read_ECPKParameters: function(out_: PFILE; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl = Load_PEM_read_ECPKParameters;
  PEM_write_bio_ECPKParameters: function(out_: PBIO; x: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_ECPKParameters;
  PEM_write_ECPKParameters: function(out_: PFILE; x: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_PEM_write_ECPKParameters;
  PEM_read_bio_ECPrivateKey: function(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl = Load_PEM_read_bio_ECPrivateKey;
  PEM_read_ECPrivateKey: function(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl = Load_PEM_read_ECPrivateKey;
  PEM_write_bio_ECPrivateKey: function(out_: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_ECPrivateKey;
  PEM_write_ECPrivateKey: function(out_: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_ECPrivateKey;
  PEM_read_bio_EC_PUBKEY: function(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl = Load_PEM_read_bio_EC_PUBKEY;
  PEM_read_EC_PUBKEY: function(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl = Load_PEM_read_EC_PUBKEY;
  PEM_write_bio_EC_PUBKEY: function(out_: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_EC_PUBKEY;
  PEM_write_EC_PUBKEY: function(out_: PFILE; x: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_EC_PUBKEY;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}
  {$ifndef  OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read_bio_DHparams(out_: PBIO; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl; external CLibCrypto name 'PEM_read_bio_DHparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_read_DHparams(out_: PFILE; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl; external CLibCrypto name 'PEM_read_DHparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_DHparams(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_DHparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_DHparams(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_DHparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_bio_DHxparams(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_DHxparams'; deprecated 'Since OpenSSL 3.0';
  function PEM_write_DHxparams(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_DHxparams'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM PEM_read_bio_DHparams}
  {$EXTERNALSYM PEM_read_DHparams}
  {$EXTERNALSYM PEM_write_bio_DHparams}
  {$EXTERNALSYM PEM_write_DHparams}
  {$EXTERNALSYM PEM_write_bio_DHxparams}
  {$EXTERNALSYM PEM_write_DHxparams}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read_bio_DHparams(out_: PBIO; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl;
  function Load_PEM_read_DHparams(out_: PFILE; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl;
  function Load_PEM_write_bio_DHparams(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_DHparams(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio_DHxparams(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_DHxparams(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl;

var
  PEM_read_bio_DHparams: function(out_: PBIO; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl = Load_PEM_read_bio_DHparams;
  PEM_read_DHparams: function(out_: PFILE; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl = Load_PEM_read_DHparams;
  PEM_write_bio_DHparams: function(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DHparams;
  PEM_write_DHparams: function(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl = Load_PEM_write_DHparams;
  PEM_write_bio_DHxparams: function(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DHxparams;
  PEM_write_DHxparams: function(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl = Load_PEM_write_DHxparams;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read_bio_PrivateKey(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_bio_PrivateKey';
  function PEM_read_bio_PrivateKey_ex(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_bio_PrivateKey_ex';
  function PEM_read_PrivateKey(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_PrivateKey';
  function PEM_read_PrivateKey_ex(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_PrivateKey_ex';
  function PEM_write_bio_PrivateKey(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PrivateKey';
  function PEM_write_bio_PrivateKey_ex(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PrivateKey_ex';
  function PEM_write_PrivateKey(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PrivateKey';
  function PEM_write_PrivateKey_ex(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PrivateKey_ex';
  function PEM_read_bio_PUBKEY(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_bio_PUBKEY';
  function PEM_read_bio_PUBKEY_ex(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_bio_PUBKEY_ex';
  function PEM_read_PUBKEY(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_PUBKEY';
  function PEM_read_PUBKEY_ex(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_PUBKEY_ex';
  function PEM_write_bio_PUBKEY(out_: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PUBKEY';
  function PEM_write_bio_PUBKEY_ex(out_: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PUBKEY_ex';
  function PEM_write_PUBKEY(out_: PFILE; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PUBKEY';
  function PEM_write_PUBKEY_ex(out_: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PUBKEY_ex';
  function PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PrivateKey_traditional';
  { Why do these take a signed char *kstr? }
  function PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PKCS8PrivateKey_nid';
  function PEM_write_bio_PKCS8PrivateKey(_param1: PBIO; _param2: PEVP_PKEY; _param3: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_PKCS8PrivateKey';
  function i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_PKCS8PrivateKey_bio';
  function i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_PKCS8PrivateKey_nid_bio';
  function d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_PKCS8PrivateKey_bio';
  {$else}
  {$EXTERNALSYM PEM_read_bio_PrivateKey}
  {$EXTERNALSYM PEM_read_bio_PrivateKey_ex}
  {$EXTERNALSYM PEM_read_PrivateKey}
  {$EXTERNALSYM PEM_read_PrivateKey_ex}
  {$EXTERNALSYM PEM_write_bio_PrivateKey}
  {$EXTERNALSYM PEM_write_bio_PrivateKey_ex}
  {$EXTERNALSYM PEM_write_PrivateKey}
  {$EXTERNALSYM PEM_write_PrivateKey_ex}
  {$EXTERNALSYM PEM_read_bio_PUBKEY}
  {$EXTERNALSYM PEM_read_bio_PUBKEY_ex}
  {$EXTERNALSYM PEM_read_PUBKEY}
  {$EXTERNALSYM PEM_read_PUBKEY_ex}
  {$EXTERNALSYM PEM_write_bio_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_PUBKEY_ex}
  {$EXTERNALSYM PEM_write_PUBKEY}
  {$EXTERNALSYM PEM_write_PUBKEY_ex}
  {$EXTERNALSYM PEM_write_bio_PrivateKey_traditional}
  {$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey_nid}
  {$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey}
  {$EXTERNALSYM i2d_PKCS8PrivateKey_bio}
  {$EXTERNALSYM i2d_PKCS8PrivateKey_nid_bio}
  {$EXTERNALSYM d2i_PKCS8PrivateKey_bio}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read_bio_PrivateKey(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
  function Load_PEM_read_bio_PrivateKey_ex(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_PEM_read_PrivateKey(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
  function Load_PEM_read_PrivateKey_ex(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_PEM_write_bio_PrivateKey(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio_PrivateKey_ex(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PrivateKey(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PrivateKey_ex(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_PEM_read_bio_PUBKEY(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
  function Load_PEM_read_bio_PUBKEY_ex(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_PEM_read_PUBKEY(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
  function Load_PEM_read_PUBKEY_ex(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_PEM_write_bio_PUBKEY(out_: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio_PUBKEY_ex(out_: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PUBKEY(out_: PFILE; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PUBKEY_ex(out_: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_bio_PKCS8PrivateKey(_param1: PBIO; _param2: PEVP_PKEY; _param3: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;

var
  PEM_read_bio_PrivateKey: function(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl = Load_PEM_read_bio_PrivateKey;
  PEM_read_bio_PrivateKey_ex: function(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_PEM_read_bio_PrivateKey_ex;
  PEM_read_PrivateKey: function(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl = Load_PEM_read_PrivateKey;
  PEM_read_PrivateKey_ex: function(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_PEM_read_PrivateKey_ex;
  PEM_write_bio_PrivateKey: function(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PrivateKey;
  PEM_write_bio_PrivateKey_ex: function(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PrivateKey_ex;
  PEM_write_PrivateKey: function(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_PrivateKey;
  PEM_write_PrivateKey_ex: function(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PEM_write_PrivateKey_ex;
  PEM_read_bio_PUBKEY: function(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl = Load_PEM_read_bio_PUBKEY;
  PEM_read_bio_PUBKEY_ex: function(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_PEM_read_bio_PUBKEY_ex;
  PEM_read_PUBKEY: function(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl = Load_PEM_read_PUBKEY;
  PEM_read_PUBKEY_ex: function(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_PEM_read_PUBKEY_ex;
  PEM_write_bio_PUBKEY: function(out_: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PUBKEY;
  PEM_write_bio_PUBKEY_ex: function(out_: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PUBKEY_ex;
  PEM_write_PUBKEY: function(out_: PFILE; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_PUBKEY;
  PEM_write_PUBKEY_ex: function(out_: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PEM_write_PUBKEY_ex;
  PEM_write_bio_PrivateKey_traditional: function(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PrivateKey_traditional;
  { Why do these take a signed char *kstr? }
  PEM_write_bio_PKCS8PrivateKey_nid: function(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8PrivateKey_nid;
  PEM_write_bio_PKCS8PrivateKey: function(_param1: PBIO; _param2: PEVP_PKEY; _param3: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8PrivateKey;
  i2d_PKCS8PrivateKey_bio: function(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKey_bio;
  i2d_PKCS8PrivateKey_nid_bio: function(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKey_nid_bio;
  d2i_PKCS8PrivateKey_bio: function(bp: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl = Load_d2i_PKCS8PrivateKey_bio;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_STDIO}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function i2d_PKCS8PrivateKey_fp(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_PKCS8PrivateKey_fp';
  function i2d_PKCS8PrivateKey_nid_fp(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_PKCS8PrivateKey_nid_fp';
  function PEM_write_PKCS8PrivateKey_nid(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PKCS8PrivateKey_nid';
  function d2i_PKCS8PrivateKey_fp(fp: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_PKCS8PrivateKey_fp';
  function PEM_write_PKCS8PrivateKey(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_PKCS8PrivateKey';
    {$else}
  {$EXTERNALSYM i2d_PKCS8PrivateKey_fp}
  {$EXTERNALSYM i2d_PKCS8PrivateKey_nid_fp}
  {$EXTERNALSYM PEM_write_PKCS8PrivateKey_nid}
  {$EXTERNALSYM d2i_PKCS8PrivateKey_fp}
  {$EXTERNALSYM PEM_write_PKCS8PrivateKey}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_i2d_PKCS8PrivateKey_fp(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_i2d_PKCS8PrivateKey_nid_fp(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_PEM_write_PKCS8PrivateKey_nid(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_d2i_PKCS8PrivateKey_fp(fp: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
  function Load_PEM_write_PKCS8PrivateKey(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;

var
  i2d_PKCS8PrivateKey_fp: function(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKey_fp;
  i2d_PKCS8PrivateKey_nid_fp: function(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKey_nid_fp;
  PEM_write_PKCS8PrivateKey_nid: function(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_PKCS8PrivateKey_nid;
  d2i_PKCS8PrivateKey_fp: function(fp: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl = Load_d2i_PKCS8PrivateKey_fp;
  PEM_write_PKCS8PrivateKey: function(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_PKCS8PrivateKey;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function PEM_read_bio_Parameters_ex(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_bio_Parameters_ex';
  function PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto name 'PEM_read_bio_Parameters';
  function PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PEM_write_bio_Parameters';
  function b2i_PrivateKey(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto name 'b2i_PrivateKey';
  function b2i_PublicKey(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto name 'b2i_PublicKey';
  function b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl; external CLibCrypto name 'b2i_PrivateKey_bio';
  function b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl; external CLibCrypto name 'b2i_PublicKey_bio';
  function i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2b_PrivateKey_bio';
  function i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2b_PublicKey_bio';
  function b2i_PVK_bio(in_: PBIO; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'b2i_PVK_bio';
  function b2i_PVK_bio_ex(in_: PBIO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'b2i_PVK_bio_ex';
  function i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2b_PVK_bio';
  function i2b_PVK_bio_ex(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2b_PVK_bio_ex';
  {$else}
  {$EXTERNALSYM PEM_read_bio_Parameters_ex}
  {$EXTERNALSYM PEM_read_bio_Parameters}
  {$EXTERNALSYM PEM_write_bio_Parameters}
  {$EXTERNALSYM b2i_PrivateKey}
  {$EXTERNALSYM b2i_PublicKey}
  {$EXTERNALSYM b2i_PrivateKey_bio}
  {$EXTERNALSYM b2i_PublicKey_bio}
  {$EXTERNALSYM i2b_PrivateKey_bio}
  {$EXTERNALSYM i2b_PublicKey_bio}
  {$EXTERNALSYM b2i_PVK_bio}
  {$EXTERNALSYM b2i_PVK_bio_ex}
  {$EXTERNALSYM i2b_PVK_bio}
  {$EXTERNALSYM i2b_PVK_bio_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_PEM_read_bio_Parameters_ex(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl;
  function Load_PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_b2i_PrivateKey(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
  function Load_b2i_PublicKey(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
  function Load_b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
  function Load_b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
  function Load_i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_b2i_PVK_bio(in_: PBIO; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
  function Load_b2i_PVK_bio_ex(in_: PBIO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
  function Load_i2b_PVK_bio_ex(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  PEM_read_bio_Parameters_ex: function(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_PEM_read_bio_Parameters_ex;
  PEM_read_bio_Parameters: function(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl = Load_PEM_read_bio_Parameters;
  PEM_write_bio_Parameters: function(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_Parameters;
  b2i_PrivateKey: function(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_b2i_PrivateKey;
  b2i_PublicKey: function(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_b2i_PublicKey;
  b2i_PrivateKey_bio: function(in_: PBIO): PEVP_PKEY; cdecl = Load_b2i_PrivateKey_bio;
  b2i_PublicKey_bio: function(in_: PBIO): PEVP_PKEY; cdecl = Load_b2i_PublicKey_bio;
  i2b_PrivateKey_bio: function(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2b_PrivateKey_bio;
  i2b_PublicKey_bio: function(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2b_PublicKey_bio;
  b2i_PVK_bio: function(in_: PBIO; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl = Load_b2i_PVK_bio;
  b2i_PVK_bio_ex: function(in_: PBIO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_b2i_PVK_bio_ex;
  i2b_PVK_bio: function(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl = Load_i2b_PVK_bio;
  i2b_PVK_bio_ex: function(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_i2b_PVK_bio_ex;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}

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

{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl;
begin
  PEM_get_EVP_CIPHER_INFO := LoadLibCryptoFunction('PEM_get_EVP_CIPHER_INFO');
  if not assigned(PEM_get_EVP_CIPHER_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_get_EVP_CIPHER_INFO');
  Result := PEM_get_EVP_CIPHER_INFO(header, cipher);
end;

function Load_PEM_do_header(cipher: PEVP_CIPHER_INFO; data: Pbyte; len: POpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_do_header := LoadLibCryptoFunction('PEM_do_header');
  if not assigned(PEM_do_header) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_do_header');
  Result := PEM_do_header(cipher, data, len, callback, u);
end;

function Load_PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PEM_read_bio := LoadLibCryptoFunction('PEM_read_bio');
  if not assigned(PEM_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio');
  Result := PEM_read_bio(bp, name, header, data, len);
end;

function Load_PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  PEM_read_bio_ex := LoadLibCryptoFunction('PEM_read_bio_ex');
  if not assigned(PEM_read_bio_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ex');
  Result := PEM_read_bio_ex(bp, name, header, data, len, flags);
end;

function Load_PEM_bytes_read_bio_secmem(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_bytes_read_bio_secmem := LoadLibCryptoFunction('PEM_bytes_read_bio_secmem');
  if not assigned(PEM_bytes_read_bio_secmem) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_bytes_read_bio_secmem');
  Result := PEM_bytes_read_bio_secmem(pdata, plen, pnm, name, bp, cb, u);
end;

function Load_PEM_write_bio(bp: PBIO; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio := LoadLibCryptoFunction('PEM_write_bio');
  if not assigned(PEM_write_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio');
  Result := PEM_write_bio(bp, name, hdr, data, len);
end;

function Load_PEM_bytes_read_bio(pdata: PPbyte; plen: POpenSSL_C_INT; pnm: PPAnsiChar; name: PAnsiChar; bp: PBIO; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_bytes_read_bio := LoadLibCryptoFunction('PEM_bytes_read_bio');
  if not assigned(PEM_bytes_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_bytes_read_bio');
  Result := PEM_bytes_read_bio(pdata, plen, pnm, name, bp, cb, u);
end;

function Load_PEM_ASN1_read_bio(d2i: Pd2i_of_void; name: PAnsiChar; bp: PBIO; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl;
begin
  PEM_ASN1_read_bio := LoadLibCryptoFunction('PEM_ASN1_read_bio');
  if not assigned(PEM_ASN1_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_read_bio');
  Result := PEM_ASN1_read_bio(d2i, name, bp, x, cb, u);
end;

function Load_PEM_ASN1_write_bio(i2d: Pi2d_of_void; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_ASN1_write_bio := LoadLibCryptoFunction('PEM_ASN1_write_bio');
  if not assigned(PEM_ASN1_write_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_write_bio');
  Result := PEM_ASN1_write_bio(i2d, name, bp, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_ASN1_write_bio_ctx(i2d: POSSL_i2d_of_void_ctx; vctx: pointer; name: PAnsiChar; bp: PBIO; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_ASN1_write_bio_ctx := LoadLibCryptoFunction('PEM_ASN1_write_bio_ctx');
  if not assigned(PEM_ASN1_write_bio_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_write_bio_ctx');
  Result := PEM_ASN1_write_bio_ctx(i2d, vctx, name, bp, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_X509_INFO_read_bio(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl;
begin
  PEM_X509_INFO_read_bio := LoadLibCryptoFunction('PEM_X509_INFO_read_bio');
  if not assigned(PEM_X509_INFO_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_read_bio');
  Result := PEM_X509_INFO_read_bio(bp, sk, cb, u);
end;

function Load_PEM_X509_INFO_read_bio_ex(bp: PBIO; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl;
begin
  PEM_X509_INFO_read_bio_ex := LoadLibCryptoFunction('PEM_X509_INFO_read_bio_ex');
  if not assigned(PEM_X509_INFO_read_bio_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_read_bio_ex');
  Result := PEM_X509_INFO_read_bio_ex(bp, sk, cb, u, libctx, propq);
end;

function Load_PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_X509_INFO_write_bio := LoadLibCryptoFunction('PEM_X509_INFO_write_bio');
  if not assigned(PEM_X509_INFO_write_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_write_bio');
  Result := PEM_X509_INFO_write_bio(bp, xi, enc, kstr, klen, cd, u);
end;

{$ifndef  OPENSSL_NO_STDIO}
function Load_PEM_read(fp: PFILE; name: PPAnsiChar; header: PPAnsiChar; data: PPbyte; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PEM_read := LoadLibCryptoFunction('PEM_read');
  if not assigned(PEM_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read');
  Result := PEM_read(fp, name, header, data, len);
end;

function Load_PEM_write(fp: PFILE; name: PAnsiChar; hdr: PAnsiChar; data: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PEM_write := LoadLibCryptoFunction('PEM_write');
  if not assigned(PEM_write) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write');
  Result := PEM_write(fp, name, hdr, data, len);
end;

function Load_PEM_ASN1_read(d2i: Pd2i_of_void; name: PAnsiChar; fp: PFILE; x: Ppointer; cb: Tpem_password_cb; u: pointer): pointer; cdecl;
begin
  PEM_ASN1_read := LoadLibCryptoFunction('PEM_ASN1_read');
  if not assigned(PEM_ASN1_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_read');
  Result := PEM_ASN1_read(d2i, name, fp, x, cb, u);
end;

function Load_PEM_ASN1_write(i2d: Pi2d_of_void; name: PAnsiChar; fp: PFILE; x: pointer; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; callback: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_ASN1_write := LoadLibCryptoFunction('PEM_ASN1_write');
  if not assigned(PEM_ASN1_write) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_write');
  Result := PEM_ASN1_write(i2d, name, fp, x, enc, kstr, klen, callback, u);
end;

function Load_PEM_X509_INFO_read(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer): Pstack_st_X509_INFO; cdecl;
begin
  PEM_X509_INFO_read := LoadLibCryptoFunction('PEM_X509_INFO_read');
  if not assigned(PEM_X509_INFO_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_read');
  Result := PEM_X509_INFO_read(fp, sk, cb, u);
end;

function Load_PEM_X509_INFO_read_ex(fp: PFILE; sk: Pstack_st_X509_INFO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): Pstack_st_X509_INFO; cdecl;
begin
  PEM_X509_INFO_read_ex := LoadLibCryptoFunction('PEM_X509_INFO_read_ex');
  if not assigned(PEM_X509_INFO_read_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_read_ex');
  Result := PEM_X509_INFO_read_ex(fp, sk, cb, u, libctx, propq);
end;

{$endif} { OPENSSL_NO_STDIO}
function Load_PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PEM_SignInit := LoadLibCryptoFunction('PEM_SignInit');
  if not assigned(PEM_SignInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignInit');
  Result := PEM_SignInit(ctx, type_);
end;

function Load_PEM_SignUpdate(ctx: PEVP_MD_CTX; d: Pbyte; cnt: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  PEM_SignUpdate := LoadLibCryptoFunction('PEM_SignUpdate');
  if not assigned(PEM_SignUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignUpdate');
  Result := PEM_SignUpdate(ctx, d, cnt);
end;

function Load_PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_SignFinal := LoadLibCryptoFunction('PEM_SignFinal');
  if not assigned(PEM_SignFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignFinal');
  Result := PEM_SignFinal(ctx, sigret, siglen, pkey);
end;

function Load_PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_def_callback := LoadLibCryptoFunction('PEM_def_callback');
  if not assigned(PEM_def_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_def_callback');
  Result := PEM_def_callback(buf, num, rwflag, userdata);
end;

procedure Load_PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl;
begin
  PEM_proc_type := LoadLibCryptoFunction('PEM_proc_type');
  if not assigned(PEM_proc_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_proc_type');
  PEM_proc_type(buf, type_);
end;

procedure Load_PEM_dek_info(buf: PAnsiChar; type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl;
begin
  PEM_dek_info := LoadLibCryptoFunction('PEM_dek_info');
  if not assigned(PEM_dek_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_dek_info');
  PEM_dek_info(buf, type_, len, str);
end;

function Load_PEM_read_bio_X509(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
begin
  PEM_read_bio_X509 := LoadLibCryptoFunction('PEM_read_bio_X509');
  if not assigned(PEM_read_bio_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509');
  Result := PEM_read_bio_X509(out_, x, cb, u);
end;

function Load_PEM_read_X509(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
begin
  PEM_read_X509 := LoadLibCryptoFunction('PEM_read_X509');
  if not assigned(PEM_read_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_X509');
  Result := PEM_read_X509(out_, x, cb, u);
end;

function Load_PEM_write_bio_X509(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509 := LoadLibCryptoFunction('PEM_write_bio_X509');
  if not assigned(PEM_write_bio_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509');
  Result := PEM_write_bio_X509(out_, x);
end;

function Load_PEM_write_X509(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_X509 := LoadLibCryptoFunction('PEM_write_X509');
  if not assigned(PEM_write_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_X509');
  Result := PEM_write_X509(out_, x);
end;

function Load_PEM_read_bio_X509_AUX(out_: PBIO; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
begin
  PEM_read_bio_X509_AUX := LoadLibCryptoFunction('PEM_read_bio_X509_AUX');
  if not assigned(PEM_read_bio_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_AUX');
  Result := PEM_read_bio_X509_AUX(out_, x, cb, u);
end;

function Load_PEM_read_X509_AUX(out_: PFILE; x: PPX509; cb: Tpem_password_cb; u: pointer): PX509; cdecl;
begin
  PEM_read_X509_AUX := LoadLibCryptoFunction('PEM_read_X509_AUX');
  if not assigned(PEM_read_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_X509_AUX');
  Result := PEM_read_X509_AUX(out_, x, cb, u);
end;

function Load_PEM_write_bio_X509_AUX(out_: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_AUX := LoadLibCryptoFunction('PEM_write_bio_X509_AUX');
  if not assigned(PEM_write_bio_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_AUX');
  Result := PEM_write_bio_X509_AUX(out_, x);
end;

function Load_PEM_write_X509_AUX(out_: PFILE; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_X509_AUX := LoadLibCryptoFunction('PEM_write_X509_AUX');
  if not assigned(PEM_write_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_X509_AUX');
  Result := PEM_write_X509_AUX(out_, x);
end;

function Load_PEM_read_bio_X509_REQ(out_: PBIO; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl;
begin
  PEM_read_bio_X509_REQ := LoadLibCryptoFunction('PEM_read_bio_X509_REQ');
  if not assigned(PEM_read_bio_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_REQ');
  Result := PEM_read_bio_X509_REQ(out_, x, cb, u);
end;

function Load_PEM_read_X509_REQ(out_: PFILE; x: PPX509_REQ; cb: Tpem_password_cb; u: pointer): PX509_REQ; cdecl;
begin
  PEM_read_X509_REQ := LoadLibCryptoFunction('PEM_read_X509_REQ');
  if not assigned(PEM_read_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_X509_REQ');
  Result := PEM_read_X509_REQ(out_, x, cb, u);
end;

function Load_PEM_write_bio_X509_REQ(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_REQ := LoadLibCryptoFunction('PEM_write_bio_X509_REQ');
  if not assigned(PEM_write_bio_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_REQ');
  Result := PEM_write_bio_X509_REQ(out_, x);
end;

function Load_PEM_write_X509_REQ(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_X509_REQ := LoadLibCryptoFunction('PEM_write_X509_REQ');
  if not assigned(PEM_write_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_X509_REQ');
  Result := PEM_write_X509_REQ(out_, x);
end;

function Load_PEM_write_bio_X509_REQ_NEW(out_: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_REQ_NEW := LoadLibCryptoFunction('PEM_write_bio_X509_REQ_NEW');
  if not assigned(PEM_write_bio_X509_REQ_NEW) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_REQ_NEW');
  Result := PEM_write_bio_X509_REQ_NEW(out_, x);
end;

function Load_PEM_write_X509_REQ_NEW(out_: PFILE; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_X509_REQ_NEW := LoadLibCryptoFunction('PEM_write_X509_REQ_NEW');
  if not assigned(PEM_write_X509_REQ_NEW) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_X509_REQ_NEW');
  Result := PEM_write_X509_REQ_NEW(out_, x);
end;

function Load_PEM_read_bio_X509_CRL(out_: PBIO; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl;
begin
  PEM_read_bio_X509_CRL := LoadLibCryptoFunction('PEM_read_bio_X509_CRL');
  if not assigned(PEM_read_bio_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_CRL');
  Result := PEM_read_bio_X509_CRL(out_, x, cb, u);
end;

function Load_PEM_read_X509_CRL(out_: PFILE; x: PPX509_CRL; cb: Tpem_password_cb; u: pointer): PX509_CRL; cdecl;
begin
  PEM_read_X509_CRL := LoadLibCryptoFunction('PEM_read_X509_CRL');
  if not assigned(PEM_read_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_X509_CRL');
  Result := PEM_read_X509_CRL(out_, x, cb, u);
end;

function Load_PEM_write_bio_X509_CRL(out_: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_CRL := LoadLibCryptoFunction('PEM_write_bio_X509_CRL');
  if not assigned(PEM_write_bio_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_CRL');
  Result := PEM_write_bio_X509_CRL(out_, x);
end;

function Load_PEM_write_X509_CRL(out_: PFILE; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_X509_CRL := LoadLibCryptoFunction('PEM_write_X509_CRL');
  if not assigned(PEM_write_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_X509_CRL');
  Result := PEM_write_X509_CRL(out_, x);
end;

function Load_PEM_read_bio_X509_PUBKEY(out_: PBIO; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl;
begin
  PEM_read_bio_X509_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_X509_PUBKEY');
  if not assigned(PEM_read_bio_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_PUBKEY');
  Result := PEM_read_bio_X509_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_read_X509_PUBKEY(out_: PFILE; x: PPX509_PUBKEY; cb: Tpem_password_cb; u: pointer): PX509_PUBKEY; cdecl;
begin
  PEM_read_X509_PUBKEY := LoadLibCryptoFunction('PEM_read_X509_PUBKEY');
  if not assigned(PEM_read_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_X509_PUBKEY');
  Result := PEM_read_X509_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_write_bio_X509_PUBKEY(out_: PBIO; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_X509_PUBKEY');
  if not assigned(PEM_write_bio_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_PUBKEY');
  Result := PEM_write_bio_X509_PUBKEY(out_, x);
end;

function Load_PEM_write_X509_PUBKEY(out_: PFILE; x: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_X509_PUBKEY := LoadLibCryptoFunction('PEM_write_X509_PUBKEY');
  if not assigned(PEM_write_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_X509_PUBKEY');
  Result := PEM_write_X509_PUBKEY(out_, x);
end;

function Load_PEM_read_bio_PKCS7(out_: PBIO; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl;
begin
  PEM_read_bio_PKCS7 := LoadLibCryptoFunction('PEM_read_bio_PKCS7');
  if not assigned(PEM_read_bio_PKCS7) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS7');
  Result := PEM_read_bio_PKCS7(out_, x, cb, u);
end;

function Load_PEM_read_PKCS7(out_: PFILE; x: PPPKCS7; cb: Tpem_password_cb; u: pointer): PPKCS7; cdecl;
begin
  PEM_read_PKCS7 := LoadLibCryptoFunction('PEM_read_PKCS7');
  if not assigned(PEM_read_PKCS7) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_PKCS7');
  Result := PEM_read_PKCS7(out_, x, cb, u);
end;

function Load_PEM_write_bio_PKCS7(out_: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS7 := LoadLibCryptoFunction('PEM_write_bio_PKCS7');
  if not assigned(PEM_write_bio_PKCS7) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS7');
  Result := PEM_write_bio_PKCS7(out_, x);
end;

function Load_PEM_write_PKCS7(out_: PFILE; x: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PKCS7 := LoadLibCryptoFunction('PEM_write_PKCS7');
  if not assigned(PEM_write_PKCS7) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PKCS7');
  Result := PEM_write_PKCS7(out_, x);
end;

function Load_PEM_read_bio_NETSCAPE_CERT_SEQUENCE(out_: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl;
begin
  PEM_read_bio_NETSCAPE_CERT_SEQUENCE := LoadLibCryptoFunction('PEM_read_bio_NETSCAPE_CERT_SEQUENCE');
  if not assigned(PEM_read_bio_NETSCAPE_CERT_SEQUENCE) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_NETSCAPE_CERT_SEQUENCE');
  Result := PEM_read_bio_NETSCAPE_CERT_SEQUENCE(out_, x, cb, u);
end;

function Load_PEM_read_NETSCAPE_CERT_SEQUENCE(out_: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: Tpem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl;
begin
  PEM_read_NETSCAPE_CERT_SEQUENCE := LoadLibCryptoFunction('PEM_read_NETSCAPE_CERT_SEQUENCE');
  if not assigned(PEM_read_NETSCAPE_CERT_SEQUENCE) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_NETSCAPE_CERT_SEQUENCE');
  Result := PEM_read_NETSCAPE_CERT_SEQUENCE(out_, x, cb, u);
end;

function Load_PEM_write_bio_NETSCAPE_CERT_SEQUENCE(out_: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_NETSCAPE_CERT_SEQUENCE := LoadLibCryptoFunction('PEM_write_bio_NETSCAPE_CERT_SEQUENCE');
  if not assigned(PEM_write_bio_NETSCAPE_CERT_SEQUENCE) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_NETSCAPE_CERT_SEQUENCE');
  Result := PEM_write_bio_NETSCAPE_CERT_SEQUENCE(out_, x);
end;

function Load_PEM_write_NETSCAPE_CERT_SEQUENCE(out_: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_NETSCAPE_CERT_SEQUENCE := LoadLibCryptoFunction('PEM_write_NETSCAPE_CERT_SEQUENCE');
  if not assigned(PEM_write_NETSCAPE_CERT_SEQUENCE) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_NETSCAPE_CERT_SEQUENCE');
  Result := PEM_write_NETSCAPE_CERT_SEQUENCE(out_, x);
end;

function Load_PEM_read_bio_PKCS8(out_: PBIO; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl;
begin
  PEM_read_bio_PKCS8 := LoadLibCryptoFunction('PEM_read_bio_PKCS8');
  if not assigned(PEM_read_bio_PKCS8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS8');
  Result := PEM_read_bio_PKCS8(out_, x, cb, u);
end;

function Load_PEM_read_PKCS8(out_: PFILE; x: PPX509_SIG; cb: Tpem_password_cb; u: pointer): PX509_SIG; cdecl;
begin
  PEM_read_PKCS8 := LoadLibCryptoFunction('PEM_read_PKCS8');
  if not assigned(PEM_read_PKCS8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_PKCS8');
  Result := PEM_read_PKCS8(out_, x, cb, u);
end;

function Load_PEM_write_bio_PKCS8(out_: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8 := LoadLibCryptoFunction('PEM_write_bio_PKCS8');
  if not assigned(PEM_write_bio_PKCS8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8');
  Result := PEM_write_bio_PKCS8(out_, x);
end;

function Load_PEM_write_PKCS8(out_: PFILE; x: PX509_SIG): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PKCS8 := LoadLibCryptoFunction('PEM_write_PKCS8');
  if not assigned(PEM_write_PKCS8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PKCS8');
  Result := PEM_write_PKCS8(out_, x);
end;

function Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO(out_: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
  if not assigned(PEM_read_bio_PKCS8_PRIV_KEY_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
  Result := PEM_read_bio_PKCS8_PRIV_KEY_INFO(out_, x, cb, u);
end;

function Load_PEM_read_PKCS8_PRIV_KEY_INFO(out_: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u: pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  PEM_read_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_read_PKCS8_PRIV_KEY_INFO');
  if not assigned(PEM_read_PKCS8_PRIV_KEY_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_PKCS8_PRIV_KEY_INFO');
  Result := PEM_read_PKCS8_PRIV_KEY_INFO(out_, x, cb, u);
end;

function Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO(out_: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
  if not assigned(PEM_write_bio_PKCS8_PRIV_KEY_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
  Result := PEM_write_bio_PKCS8_PRIV_KEY_INFO(out_, x);
end;

function Load_PEM_write_PKCS8_PRIV_KEY_INFO(out_: PFILE; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_write_PKCS8_PRIV_KEY_INFO');
  if not assigned(PEM_write_PKCS8_PRIV_KEY_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PKCS8_PRIV_KEY_INFO');
  Result := PEM_write_PKCS8_PRIV_KEY_INFO(out_, x);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_PEM_read_bio_RSAPrivateKey(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
begin
  PEM_read_bio_RSAPrivateKey := LoadLibCryptoFunction('PEM_read_bio_RSAPrivateKey');
  if not assigned(PEM_read_bio_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSAPrivateKey');
  Result := PEM_read_bio_RSAPrivateKey(out_, x, cb, u);
end;

function Load_PEM_read_RSAPrivateKey(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
begin
  PEM_read_RSAPrivateKey := LoadLibCryptoFunction('PEM_read_RSAPrivateKey');
  if not assigned(PEM_read_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_RSAPrivateKey');
  Result := PEM_read_RSAPrivateKey(out_, x, cb, u);
end;

function Load_PEM_write_bio_RSAPrivateKey(out_: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_RSAPrivateKey := LoadLibCryptoFunction('PEM_write_bio_RSAPrivateKey');
  if not assigned(PEM_write_bio_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSAPrivateKey');
  Result := PEM_write_bio_RSAPrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_write_RSAPrivateKey(out_: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_RSAPrivateKey := LoadLibCryptoFunction('PEM_write_RSAPrivateKey');
  if not assigned(PEM_write_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_RSAPrivateKey');
  Result := PEM_write_RSAPrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_read_bio_RSAPublicKey(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
begin
  PEM_read_bio_RSAPublicKey := LoadLibCryptoFunction('PEM_read_bio_RSAPublicKey');
  if not assigned(PEM_read_bio_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSAPublicKey');
  Result := PEM_read_bio_RSAPublicKey(out_, x, cb, u);
end;

function Load_PEM_read_RSAPublicKey(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
begin
  PEM_read_RSAPublicKey := LoadLibCryptoFunction('PEM_read_RSAPublicKey');
  if not assigned(PEM_read_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_RSAPublicKey');
  Result := PEM_read_RSAPublicKey(out_, x, cb, u);
end;

function Load_PEM_write_bio_RSAPublicKey(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_RSAPublicKey := LoadLibCryptoFunction('PEM_write_bio_RSAPublicKey');
  if not assigned(PEM_write_bio_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSAPublicKey');
  Result := PEM_write_bio_RSAPublicKey(out_, x);
end;

function Load_PEM_write_RSAPublicKey(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_RSAPublicKey := LoadLibCryptoFunction('PEM_write_RSAPublicKey');
  if not assigned(PEM_write_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_RSAPublicKey');
  Result := PEM_write_RSAPublicKey(out_, x);
end;

function Load_PEM_read_bio_RSA_PUBKEY(out_: PBIO; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
begin
  PEM_read_bio_RSA_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_RSA_PUBKEY');
  if not assigned(PEM_read_bio_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSA_PUBKEY');
  Result := PEM_read_bio_RSA_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_read_RSA_PUBKEY(out_: PFILE; x: PPRSA; cb: Tpem_password_cb; u: pointer): PRSA; cdecl;
begin
  PEM_read_RSA_PUBKEY := LoadLibCryptoFunction('PEM_read_RSA_PUBKEY');
  if not assigned(PEM_read_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_RSA_PUBKEY');
  Result := PEM_read_RSA_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_write_bio_RSA_PUBKEY(out_: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_RSA_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_RSA_PUBKEY');
  if not assigned(PEM_write_bio_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSA_PUBKEY');
  Result := PEM_write_bio_RSA_PUBKEY(out_, x);
end;

function Load_PEM_write_RSA_PUBKEY(out_: PFILE; x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_RSA_PUBKEY := LoadLibCryptoFunction('PEM_write_RSA_PUBKEY');
  if not assigned(PEM_write_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_RSA_PUBKEY');
  Result := PEM_write_RSA_PUBKEY(out_, x);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DSA}
function Load_PEM_read_bio_DSAPrivateKey(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
begin
  PEM_read_bio_DSAPrivateKey := LoadLibCryptoFunction('PEM_read_bio_DSAPrivateKey');
  if not assigned(PEM_read_bio_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSAPrivateKey');
  Result := PEM_read_bio_DSAPrivateKey(out_, x, cb, u);
end;

function Load_PEM_read_DSAPrivateKey(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
begin
  PEM_read_DSAPrivateKey := LoadLibCryptoFunction('PEM_read_DSAPrivateKey');
  if not assigned(PEM_read_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_DSAPrivateKey');
  Result := PEM_read_DSAPrivateKey(out_, x, cb, u);
end;

function Load_PEM_write_bio_DSAPrivateKey(out_: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DSAPrivateKey := LoadLibCryptoFunction('PEM_write_bio_DSAPrivateKey');
  if not assigned(PEM_write_bio_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSAPrivateKey');
  Result := PEM_write_bio_DSAPrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_write_DSAPrivateKey(out_: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_DSAPrivateKey := LoadLibCryptoFunction('PEM_write_DSAPrivateKey');
  if not assigned(PEM_write_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_DSAPrivateKey');
  Result := PEM_write_DSAPrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_read_bio_DSA_PUBKEY(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
begin
  PEM_read_bio_DSA_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_DSA_PUBKEY');
  if not assigned(PEM_read_bio_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSA_PUBKEY');
  Result := PEM_read_bio_DSA_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_read_DSA_PUBKEY(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
begin
  PEM_read_DSA_PUBKEY := LoadLibCryptoFunction('PEM_read_DSA_PUBKEY');
  if not assigned(PEM_read_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_DSA_PUBKEY');
  Result := PEM_read_DSA_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_write_bio_DSA_PUBKEY(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DSA_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_DSA_PUBKEY');
  if not assigned(PEM_write_bio_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSA_PUBKEY');
  Result := PEM_write_bio_DSA_PUBKEY(out_, x);
end;

function Load_PEM_write_DSA_PUBKEY(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_DSA_PUBKEY := LoadLibCryptoFunction('PEM_write_DSA_PUBKEY');
  if not assigned(PEM_write_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_DSA_PUBKEY');
  Result := PEM_write_DSA_PUBKEY(out_, x);
end;

function Load_PEM_read_bio_DSAparams(out_: PBIO; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
begin
  PEM_read_bio_DSAparams := LoadLibCryptoFunction('PEM_read_bio_DSAparams');
  if not assigned(PEM_read_bio_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSAparams');
  Result := PEM_read_bio_DSAparams(out_, x, cb, u);
end;

function Load_PEM_read_DSAparams(out_: PFILE; x: PPDSA; cb: Tpem_password_cb; u: pointer): PDSA; cdecl;
begin
  PEM_read_DSAparams := LoadLibCryptoFunction('PEM_read_DSAparams');
  if not assigned(PEM_read_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_DSAparams');
  Result := PEM_read_DSAparams(out_, x, cb, u);
end;

function Load_PEM_write_bio_DSAparams(out_: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DSAparams := LoadLibCryptoFunction('PEM_write_bio_DSAparams');
  if not assigned(PEM_write_bio_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSAparams');
  Result := PEM_write_bio_DSAparams(out_, x);
end;

function Load_PEM_write_DSAparams(out_: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_DSAparams := LoadLibCryptoFunction('PEM_write_DSAparams');
  if not assigned(PEM_write_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_DSAparams');
  Result := PEM_write_DSAparams(out_, x);
end;

    {$endif} { OPENSSL_NO_DSA}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_EC}
function Load_PEM_read_bio_ECPKParameters(out_: PBIO; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl;
begin
  PEM_read_bio_ECPKParameters := LoadLibCryptoFunction('PEM_read_bio_ECPKParameters');
  if not assigned(PEM_read_bio_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ECPKParameters');
  Result := PEM_read_bio_ECPKParameters(out_, x, cb, u);
end;

function Load_PEM_read_ECPKParameters(out_: PFILE; x: PPEC_GROUP; cb: Tpem_password_cb; u: pointer): PEC_GROUP; cdecl;
begin
  PEM_read_ECPKParameters := LoadLibCryptoFunction('PEM_read_ECPKParameters');
  if not assigned(PEM_read_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_ECPKParameters');
  Result := PEM_read_ECPKParameters(out_, x, cb, u);
end;

function Load_PEM_write_bio_ECPKParameters(out_: PBIO; x: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_ECPKParameters := LoadLibCryptoFunction('PEM_write_bio_ECPKParameters');
  if not assigned(PEM_write_bio_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ECPKParameters');
  Result := PEM_write_bio_ECPKParameters(out_, x);
end;

function Load_PEM_write_ECPKParameters(out_: PFILE; x: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_ECPKParameters := LoadLibCryptoFunction('PEM_write_ECPKParameters');
  if not assigned(PEM_write_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_ECPKParameters');
  Result := PEM_write_ECPKParameters(out_, x);
end;

function Load_PEM_read_bio_ECPrivateKey(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
begin
  PEM_read_bio_ECPrivateKey := LoadLibCryptoFunction('PEM_read_bio_ECPrivateKey');
  if not assigned(PEM_read_bio_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ECPrivateKey');
  Result := PEM_read_bio_ECPrivateKey(out_, x, cb, u);
end;

function Load_PEM_read_ECPrivateKey(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
begin
  PEM_read_ECPrivateKey := LoadLibCryptoFunction('PEM_read_ECPrivateKey');
  if not assigned(PEM_read_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_ECPrivateKey');
  Result := PEM_read_ECPrivateKey(out_, x, cb, u);
end;

function Load_PEM_write_bio_ECPrivateKey(out_: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_ECPrivateKey := LoadLibCryptoFunction('PEM_write_bio_ECPrivateKey');
  if not assigned(PEM_write_bio_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ECPrivateKey');
  Result := PEM_write_bio_ECPrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_write_ECPrivateKey(out_: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_ECPrivateKey := LoadLibCryptoFunction('PEM_write_ECPrivateKey');
  if not assigned(PEM_write_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_ECPrivateKey');
  Result := PEM_write_ECPrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_read_bio_EC_PUBKEY(out_: PBIO; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
begin
  PEM_read_bio_EC_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_EC_PUBKEY');
  if not assigned(PEM_read_bio_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_EC_PUBKEY');
  Result := PEM_read_bio_EC_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_read_EC_PUBKEY(out_: PFILE; x: PPEC_KEY; cb: Tpem_password_cb; u: pointer): PEC_KEY; cdecl;
begin
  PEM_read_EC_PUBKEY := LoadLibCryptoFunction('PEM_read_EC_PUBKEY');
  if not assigned(PEM_read_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_EC_PUBKEY');
  Result := PEM_read_EC_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_write_bio_EC_PUBKEY(out_: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_EC_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_EC_PUBKEY');
  if not assigned(PEM_write_bio_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_EC_PUBKEY');
  Result := PEM_write_bio_EC_PUBKEY(out_, x);
end;

function Load_PEM_write_EC_PUBKEY(out_: PFILE; x: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_EC_PUBKEY := LoadLibCryptoFunction('PEM_write_EC_PUBKEY');
  if not assigned(PEM_write_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_EC_PUBKEY');
  Result := PEM_write_EC_PUBKEY(out_, x);
end;

    {$endif} { OPENSSL_NO_EC}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_PEM_read_bio_DHparams(out_: PBIO; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl;
begin
  PEM_read_bio_DHparams := LoadLibCryptoFunction('PEM_read_bio_DHparams');
  if not assigned(PEM_read_bio_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DHparams');
  Result := PEM_read_bio_DHparams(out_, x, cb, u);
end;

function Load_PEM_read_DHparams(out_: PFILE; x: PPDH; cb: Tpem_password_cb; u: pointer): PDH; cdecl;
begin
  PEM_read_DHparams := LoadLibCryptoFunction('PEM_read_DHparams');
  if not assigned(PEM_read_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_DHparams');
  Result := PEM_read_DHparams(out_, x, cb, u);
end;

function Load_PEM_write_bio_DHparams(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DHparams := LoadLibCryptoFunction('PEM_write_bio_DHparams');
  if not assigned(PEM_write_bio_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DHparams');
  Result := PEM_write_bio_DHparams(out_, x);
end;

function Load_PEM_write_DHparams(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_DHparams := LoadLibCryptoFunction('PEM_write_DHparams');
  if not assigned(PEM_write_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_DHparams');
  Result := PEM_write_DHparams(out_, x);
end;

function Load_PEM_write_bio_DHxparams(out_: PBIO; x: PDH): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DHxparams := LoadLibCryptoFunction('PEM_write_bio_DHxparams');
  if not assigned(PEM_write_bio_DHxparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DHxparams');
  Result := PEM_write_bio_DHxparams(out_, x);
end;

function Load_PEM_write_DHxparams(out_: PFILE; x: PDH): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_DHxparams := LoadLibCryptoFunction('PEM_write_DHxparams');
  if not assigned(PEM_write_DHxparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_DHxparams');
  Result := PEM_write_DHxparams(out_, x);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DH}
function Load_PEM_read_bio_PrivateKey(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_PrivateKey := LoadLibCryptoFunction('PEM_read_bio_PrivateKey');
  if not assigned(PEM_read_bio_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PrivateKey');
  Result := PEM_read_bio_PrivateKey(out_, x, cb, u);
end;

function Load_PEM_read_bio_PrivateKey_ex(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_PrivateKey_ex := LoadLibCryptoFunction('PEM_read_bio_PrivateKey_ex');
  if not assigned(PEM_read_bio_PrivateKey_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PrivateKey_ex');
  Result := PEM_read_bio_PrivateKey_ex(out_, x, cb, u, libctx, propq);
end;

function Load_PEM_read_PrivateKey(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
begin
  PEM_read_PrivateKey := LoadLibCryptoFunction('PEM_read_PrivateKey');
  if not assigned(PEM_read_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_PrivateKey');
  Result := PEM_read_PrivateKey(out_, x, cb, u);
end;

function Load_PEM_read_PrivateKey_ex(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  PEM_read_PrivateKey_ex := LoadLibCryptoFunction('PEM_read_PrivateKey_ex');
  if not assigned(PEM_read_PrivateKey_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_PrivateKey_ex');
  Result := PEM_read_PrivateKey_ex(out_, x, cb, u, libctx, propq);
end;

function Load_PEM_write_bio_PrivateKey(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PrivateKey := LoadLibCryptoFunction('PEM_write_bio_PrivateKey');
  if not assigned(PEM_write_bio_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PrivateKey');
  Result := PEM_write_bio_PrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_write_bio_PrivateKey_ex(out_: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PrivateKey_ex := LoadLibCryptoFunction('PEM_write_bio_PrivateKey_ex');
  if not assigned(PEM_write_bio_PrivateKey_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PrivateKey_ex');
  Result := PEM_write_bio_PrivateKey_ex(out_, x, enc, kstr, klen, cb, u, libctx, propq);
end;

function Load_PEM_write_PrivateKey(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PrivateKey := LoadLibCryptoFunction('PEM_write_PrivateKey');
  if not assigned(PEM_write_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PrivateKey');
  Result := PEM_write_PrivateKey(out_, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_write_PrivateKey_ex(out_: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PrivateKey_ex := LoadLibCryptoFunction('PEM_write_PrivateKey_ex');
  if not assigned(PEM_write_PrivateKey_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PrivateKey_ex');
  Result := PEM_write_PrivateKey_ex(out_, x, enc, kstr, klen, cb, u, libctx, propq);
end;

function Load_PEM_read_bio_PUBKEY(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_PUBKEY');
  if not assigned(PEM_read_bio_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PUBKEY');
  Result := PEM_read_bio_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_read_bio_PUBKEY_ex(out_: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_PUBKEY_ex := LoadLibCryptoFunction('PEM_read_bio_PUBKEY_ex');
  if not assigned(PEM_read_bio_PUBKEY_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PUBKEY_ex');
  Result := PEM_read_bio_PUBKEY_ex(out_, x, cb, u, libctx, propq);
end;

function Load_PEM_read_PUBKEY(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
begin
  PEM_read_PUBKEY := LoadLibCryptoFunction('PEM_read_PUBKEY');
  if not assigned(PEM_read_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_PUBKEY');
  Result := PEM_read_PUBKEY(out_, x, cb, u);
end;

function Load_PEM_read_PUBKEY_ex(out_: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  PEM_read_PUBKEY_ex := LoadLibCryptoFunction('PEM_read_PUBKEY_ex');
  if not assigned(PEM_read_PUBKEY_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_PUBKEY_ex');
  Result := PEM_read_PUBKEY_ex(out_, x, cb, u, libctx, propq);
end;

function Load_PEM_write_bio_PUBKEY(out_: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_PUBKEY');
  if not assigned(PEM_write_bio_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PUBKEY');
  Result := PEM_write_bio_PUBKEY(out_, x);
end;

function Load_PEM_write_bio_PUBKEY_ex(out_: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PUBKEY_ex := LoadLibCryptoFunction('PEM_write_bio_PUBKEY_ex');
  if not assigned(PEM_write_bio_PUBKEY_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PUBKEY_ex');
  Result := PEM_write_bio_PUBKEY_ex(out_, x, libctx, propq);
end;

function Load_PEM_write_PUBKEY(out_: PFILE; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PUBKEY := LoadLibCryptoFunction('PEM_write_PUBKEY');
  if not assigned(PEM_write_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PUBKEY');
  Result := PEM_write_PUBKEY(out_, x);
end;

function Load_PEM_write_PUBKEY_ex(out_: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PUBKEY_ex := LoadLibCryptoFunction('PEM_write_PUBKEY_ex');
  if not assigned(PEM_write_PUBKEY_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PUBKEY_ex');
  Result := PEM_write_PUBKEY_ex(out_, x, libctx, propq);
end;

function Load_PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: Pbyte; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PrivateKey_traditional := LoadLibCryptoFunction('PEM_write_bio_PrivateKey_traditional');
  if not assigned(PEM_write_bio_PrivateKey_traditional) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PrivateKey_traditional');
  Result := PEM_write_bio_PrivateKey_traditional(bp, x, enc, kstr, klen, cb, u);
end;

function Load_PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8PrivateKey_nid := LoadLibCryptoFunction('PEM_write_bio_PKCS8PrivateKey_nid');
  if not assigned(PEM_write_bio_PKCS8PrivateKey_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8PrivateKey_nid');
  Result := PEM_write_bio_PKCS8PrivateKey_nid(bp, x, nid, kstr, klen, cb, u);
end;

function Load_PEM_write_bio_PKCS8PrivateKey(_param1: PBIO; _param2: PEVP_PKEY; _param3: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8PrivateKey := LoadLibCryptoFunction('PEM_write_bio_PKCS8PrivateKey');
  if not assigned(PEM_write_bio_PKCS8PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8PrivateKey');
  Result := PEM_write_bio_PKCS8PrivateKey(_param1, _param2, _param3, kstr, klen, cb, u);
end;

function Load_i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKey_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_bio');
  if not assigned(i2d_PKCS8PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_bio');
  Result := i2d_PKCS8PrivateKey_bio(bp, x, enc, kstr, klen, cb, u);
end;

function Load_i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKey_nid_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_nid_bio');
  if not assigned(i2d_PKCS8PrivateKey_nid_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_nid_bio');
  Result := i2d_PKCS8PrivateKey_nid_bio(bp, x, nid, kstr, klen, cb, u);
end;

function Load_d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
begin
  d2i_PKCS8PrivateKey_bio := LoadLibCryptoFunction('d2i_PKCS8PrivateKey_bio');
  if not assigned(d2i_PKCS8PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8PrivateKey_bio');
  Result := d2i_PKCS8PrivateKey_bio(bp, x, cb, u);
end;

{$ifndef  OPENSSL_NO_STDIO}
function Load_i2d_PKCS8PrivateKey_fp(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKey_fp := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_fp');
  if not assigned(i2d_PKCS8PrivateKey_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_fp');
  Result := i2d_PKCS8PrivateKey_fp(fp, x, enc, kstr, klen, cb, u);
end;

function Load_i2d_PKCS8PrivateKey_nid_fp(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKey_nid_fp := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_nid_fp');
  if not assigned(i2d_PKCS8PrivateKey_nid_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_nid_fp');
  Result := i2d_PKCS8PrivateKey_nid_fp(fp, x, nid, kstr, klen, cb, u);
end;

function Load_PEM_write_PKCS8PrivateKey_nid(fp: PFILE; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PKCS8PrivateKey_nid := LoadLibCryptoFunction('PEM_write_PKCS8PrivateKey_nid');
  if not assigned(PEM_write_PKCS8PrivateKey_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PKCS8PrivateKey_nid');
  Result := PEM_write_PKCS8PrivateKey_nid(fp, x, nid, kstr, klen, cb, u);
end;

function Load_d2i_PKCS8PrivateKey_fp(fp: PFILE; x: PPEVP_PKEY; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
begin
  d2i_PKCS8PrivateKey_fp := LoadLibCryptoFunction('d2i_PKCS8PrivateKey_fp');
  if not assigned(d2i_PKCS8PrivateKey_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8PrivateKey_fp');
  Result := d2i_PKCS8PrivateKey_fp(fp, x, cb, u);
end;

function Load_PEM_write_PKCS8PrivateKey(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cd: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_PKCS8PrivateKey := LoadLibCryptoFunction('PEM_write_PKCS8PrivateKey');
  if not assigned(PEM_write_PKCS8PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_PKCS8PrivateKey');
  Result := PEM_write_PKCS8PrivateKey(fp, x, enc, kstr, klen, cd, u);
end;

{$endif} { OPENSSL_NO_STDIO}
function Load_PEM_read_bio_Parameters_ex(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_Parameters_ex := LoadLibCryptoFunction('PEM_read_bio_Parameters_ex');
  if not assigned(PEM_read_bio_Parameters_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_Parameters_ex');
  Result := PEM_read_bio_Parameters_ex(bp, x, libctx, propq);
end;

function Load_PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_Parameters := LoadLibCryptoFunction('PEM_read_bio_Parameters');
  if not assigned(PEM_read_bio_Parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_Parameters');
  Result := PEM_read_bio_Parameters(bp, x);
end;

function Load_PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_Parameters := LoadLibCryptoFunction('PEM_write_bio_Parameters');
  if not assigned(PEM_write_bio_Parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_Parameters');
  Result := PEM_write_bio_Parameters(bp, x);
end;

function Load_b2i_PrivateKey(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  b2i_PrivateKey := LoadLibCryptoFunction('b2i_PrivateKey');
  if not assigned(b2i_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PrivateKey');
  Result := b2i_PrivateKey(in_, length);
end;

function Load_b2i_PublicKey(in_: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  b2i_PublicKey := LoadLibCryptoFunction('b2i_PublicKey');
  if not assigned(b2i_PublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PublicKey');
  Result := b2i_PublicKey(in_, length);
end;

function Load_b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
begin
  b2i_PrivateKey_bio := LoadLibCryptoFunction('b2i_PrivateKey_bio');
  if not assigned(b2i_PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PrivateKey_bio');
  Result := b2i_PrivateKey_bio(in_);
end;

function Load_b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
begin
  b2i_PublicKey_bio := LoadLibCryptoFunction('b2i_PublicKey_bio');
  if not assigned(b2i_PublicKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PublicKey_bio');
  Result := b2i_PublicKey_bio(in_);
end;

function Load_i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2b_PrivateKey_bio := LoadLibCryptoFunction('i2b_PrivateKey_bio');
  if not assigned(i2b_PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PrivateKey_bio');
  Result := i2b_PrivateKey_bio(out_, pk);
end;

function Load_i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2b_PublicKey_bio := LoadLibCryptoFunction('i2b_PublicKey_bio');
  if not assigned(i2b_PublicKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PublicKey_bio');
  Result := i2b_PublicKey_bio(out_, pk);
end;

function Load_b2i_PVK_bio(in_: PBIO; cb: Tpem_password_cb; u: pointer): PEVP_PKEY; cdecl;
begin
  b2i_PVK_bio := LoadLibCryptoFunction('b2i_PVK_bio');
  if not assigned(b2i_PVK_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PVK_bio');
  Result := b2i_PVK_bio(in_, cb, u);
end;

function Load_b2i_PVK_bio_ex(in_: PBIO; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  b2i_PVK_bio_ex := LoadLibCryptoFunction('b2i_PVK_bio_ex');
  if not assigned(b2i_PVK_bio_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PVK_bio_ex');
  Result := b2i_PVK_bio_ex(in_, cb, u, libctx, propq);
end;

function Load_i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer): TOpenSSL_C_INT; cdecl;
begin
  i2b_PVK_bio := LoadLibCryptoFunction('i2b_PVK_bio');
  if not assigned(i2b_PVK_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PVK_bio');
  Result := i2b_PVK_bio(out_, pk, enclevel, cb, u);
end;

function Load_i2b_PVK_bio_ex(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: Tpem_password_cb; u: pointer; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  i2b_PVK_bio_ex := LoadLibCryptoFunction('i2b_PVK_bio_ex');
  if not assigned(i2b_PVK_bio_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PVK_bio_ex');
  Result := i2b_PVK_bio_ex(out_, pk, enclevel, cb, u, libctx, propq);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  PEM_get_EVP_CIPHER_INFO := Load_PEM_get_EVP_CIPHER_INFO;
  PEM_do_header := Load_PEM_do_header;
  PEM_read_bio := Load_PEM_read_bio;
  PEM_read_bio_ex := Load_PEM_read_bio_ex;
  PEM_bytes_read_bio_secmem := Load_PEM_bytes_read_bio_secmem;
  PEM_write_bio := Load_PEM_write_bio;
  PEM_bytes_read_bio := Load_PEM_bytes_read_bio;
  PEM_ASN1_read_bio := Load_PEM_ASN1_read_bio;
  PEM_ASN1_write_bio := Load_PEM_ASN1_write_bio;
  PEM_ASN1_write_bio_ctx := Load_PEM_ASN1_write_bio_ctx;
  PEM_X509_INFO_read_bio := Load_PEM_X509_INFO_read_bio;
  PEM_X509_INFO_read_bio_ex := Load_PEM_X509_INFO_read_bio_ex;
  PEM_X509_INFO_write_bio := Load_PEM_X509_INFO_write_bio;
{$ifndef  OPENSSL_NO_STDIO}
  PEM_read := Load_PEM_read;
  PEM_write := Load_PEM_write;
  PEM_ASN1_read := Load_PEM_ASN1_read;
  PEM_ASN1_write := Load_PEM_ASN1_write;
  PEM_X509_INFO_read := Load_PEM_X509_INFO_read;
  PEM_X509_INFO_read_ex := Load_PEM_X509_INFO_read_ex;
{$endif} { OPENSSL_NO_STDIO}
  PEM_SignInit := Load_PEM_SignInit;
  PEM_SignUpdate := Load_PEM_SignUpdate;
  PEM_SignFinal := Load_PEM_SignFinal;
  PEM_def_callback := Load_PEM_def_callback;
  PEM_proc_type := Load_PEM_proc_type;
  PEM_dek_info := Load_PEM_dek_info;
  PEM_read_bio_X509 := Load_PEM_read_bio_X509;
  PEM_read_X509 := Load_PEM_read_X509;
  PEM_write_bio_X509 := Load_PEM_write_bio_X509;
  PEM_write_X509 := Load_PEM_write_X509;
  PEM_read_bio_X509_AUX := Load_PEM_read_bio_X509_AUX;
  PEM_read_X509_AUX := Load_PEM_read_X509_AUX;
  PEM_write_bio_X509_AUX := Load_PEM_write_bio_X509_AUX;
  PEM_write_X509_AUX := Load_PEM_write_X509_AUX;
  PEM_read_bio_X509_REQ := Load_PEM_read_bio_X509_REQ;
  PEM_read_X509_REQ := Load_PEM_read_X509_REQ;
  PEM_write_bio_X509_REQ := Load_PEM_write_bio_X509_REQ;
  PEM_write_X509_REQ := Load_PEM_write_X509_REQ;
  PEM_write_bio_X509_REQ_NEW := Load_PEM_write_bio_X509_REQ_NEW;
  PEM_write_X509_REQ_NEW := Load_PEM_write_X509_REQ_NEW;
  PEM_read_bio_X509_CRL := Load_PEM_read_bio_X509_CRL;
  PEM_read_X509_CRL := Load_PEM_read_X509_CRL;
  PEM_write_bio_X509_CRL := Load_PEM_write_bio_X509_CRL;
  PEM_write_X509_CRL := Load_PEM_write_X509_CRL;
  PEM_read_bio_X509_PUBKEY := Load_PEM_read_bio_X509_PUBKEY;
  PEM_read_X509_PUBKEY := Load_PEM_read_X509_PUBKEY;
  PEM_write_bio_X509_PUBKEY := Load_PEM_write_bio_X509_PUBKEY;
  PEM_write_X509_PUBKEY := Load_PEM_write_X509_PUBKEY;
  PEM_read_bio_PKCS7 := Load_PEM_read_bio_PKCS7;
  PEM_read_PKCS7 := Load_PEM_read_PKCS7;
  PEM_write_bio_PKCS7 := Load_PEM_write_bio_PKCS7;
  PEM_write_PKCS7 := Load_PEM_write_PKCS7;
  PEM_read_bio_NETSCAPE_CERT_SEQUENCE := Load_PEM_read_bio_NETSCAPE_CERT_SEQUENCE;
  PEM_read_NETSCAPE_CERT_SEQUENCE := Load_PEM_read_NETSCAPE_CERT_SEQUENCE;
  PEM_write_bio_NETSCAPE_CERT_SEQUENCE := Load_PEM_write_bio_NETSCAPE_CERT_SEQUENCE;
  PEM_write_NETSCAPE_CERT_SEQUENCE := Load_PEM_write_NETSCAPE_CERT_SEQUENCE;
  PEM_read_bio_PKCS8 := Load_PEM_read_bio_PKCS8;
  PEM_read_PKCS8 := Load_PEM_read_PKCS8;
  PEM_write_bio_PKCS8 := Load_PEM_write_bio_PKCS8;
  PEM_write_PKCS8 := Load_PEM_write_PKCS8;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
  PEM_read_PKCS8_PRIV_KEY_INFO := Load_PEM_read_PKCS8_PRIV_KEY_INFO;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
  PEM_write_PKCS8_PRIV_KEY_INFO := Load_PEM_write_PKCS8_PRIV_KEY_INFO;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  PEM_read_bio_RSAPrivateKey := Load_PEM_read_bio_RSAPrivateKey;
  PEM_read_RSAPrivateKey := Load_PEM_read_RSAPrivateKey;
  PEM_write_bio_RSAPrivateKey := Load_PEM_write_bio_RSAPrivateKey;
  PEM_write_RSAPrivateKey := Load_PEM_write_RSAPrivateKey;
  PEM_read_bio_RSAPublicKey := Load_PEM_read_bio_RSAPublicKey;
  PEM_read_RSAPublicKey := Load_PEM_read_RSAPublicKey;
  PEM_write_bio_RSAPublicKey := Load_PEM_write_bio_RSAPublicKey;
  PEM_write_RSAPublicKey := Load_PEM_write_RSAPublicKey;
  PEM_read_bio_RSA_PUBKEY := Load_PEM_read_bio_RSA_PUBKEY;
  PEM_read_RSA_PUBKEY := Load_PEM_read_RSA_PUBKEY;
  PEM_write_bio_RSA_PUBKEY := Load_PEM_write_bio_RSA_PUBKEY;
  PEM_write_RSA_PUBKEY := Load_PEM_write_RSA_PUBKEY;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DSA}
  PEM_read_bio_DSAPrivateKey := Load_PEM_read_bio_DSAPrivateKey;
  PEM_read_DSAPrivateKey := Load_PEM_read_DSAPrivateKey;
  PEM_write_bio_DSAPrivateKey := Load_PEM_write_bio_DSAPrivateKey;
  PEM_write_DSAPrivateKey := Load_PEM_write_DSAPrivateKey;
  PEM_read_bio_DSA_PUBKEY := Load_PEM_read_bio_DSA_PUBKEY;
  PEM_read_DSA_PUBKEY := Load_PEM_read_DSA_PUBKEY;
  PEM_write_bio_DSA_PUBKEY := Load_PEM_write_bio_DSA_PUBKEY;
  PEM_write_DSA_PUBKEY := Load_PEM_write_DSA_PUBKEY;
  PEM_read_bio_DSAparams := Load_PEM_read_bio_DSAparams;
  PEM_read_DSAparams := Load_PEM_read_DSAparams;
  PEM_write_bio_DSAparams := Load_PEM_write_bio_DSAparams;
  PEM_write_DSAparams := Load_PEM_write_DSAparams;
    {$endif} { OPENSSL_NO_DSA}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_EC}
  PEM_read_bio_ECPKParameters := Load_PEM_read_bio_ECPKParameters;
  PEM_read_ECPKParameters := Load_PEM_read_ECPKParameters;
  PEM_write_bio_ECPKParameters := Load_PEM_write_bio_ECPKParameters;
  PEM_write_ECPKParameters := Load_PEM_write_ECPKParameters;
  PEM_read_bio_ECPrivateKey := Load_PEM_read_bio_ECPrivateKey;
  PEM_read_ECPrivateKey := Load_PEM_read_ECPrivateKey;
  PEM_write_bio_ECPrivateKey := Load_PEM_write_bio_ECPrivateKey;
  PEM_write_ECPrivateKey := Load_PEM_write_ECPrivateKey;
  PEM_read_bio_EC_PUBKEY := Load_PEM_read_bio_EC_PUBKEY;
  PEM_read_EC_PUBKEY := Load_PEM_read_EC_PUBKEY;
  PEM_write_bio_EC_PUBKEY := Load_PEM_write_bio_EC_PUBKEY;
  PEM_write_EC_PUBKEY := Load_PEM_write_EC_PUBKEY;
    {$endif} { OPENSSL_NO_EC}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  PEM_read_bio_DHparams := Load_PEM_read_bio_DHparams;
  PEM_read_DHparams := Load_PEM_read_DHparams;
  PEM_write_bio_DHparams := Load_PEM_write_bio_DHparams;
  PEM_write_DHparams := Load_PEM_write_DHparams;
  PEM_write_bio_DHxparams := Load_PEM_write_bio_DHxparams;
  PEM_write_DHxparams := Load_PEM_write_DHxparams;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DH}
  PEM_read_bio_PrivateKey := Load_PEM_read_bio_PrivateKey;
  PEM_read_bio_PrivateKey_ex := Load_PEM_read_bio_PrivateKey_ex;
  PEM_read_PrivateKey := Load_PEM_read_PrivateKey;
  PEM_read_PrivateKey_ex := Load_PEM_read_PrivateKey_ex;
  PEM_write_bio_PrivateKey := Load_PEM_write_bio_PrivateKey;
  PEM_write_bio_PrivateKey_ex := Load_PEM_write_bio_PrivateKey_ex;
  PEM_write_PrivateKey := Load_PEM_write_PrivateKey;
  PEM_write_PrivateKey_ex := Load_PEM_write_PrivateKey_ex;
  PEM_read_bio_PUBKEY := Load_PEM_read_bio_PUBKEY;
  PEM_read_bio_PUBKEY_ex := Load_PEM_read_bio_PUBKEY_ex;
  PEM_read_PUBKEY := Load_PEM_read_PUBKEY;
  PEM_read_PUBKEY_ex := Load_PEM_read_PUBKEY_ex;
  PEM_write_bio_PUBKEY := Load_PEM_write_bio_PUBKEY;
  PEM_write_bio_PUBKEY_ex := Load_PEM_write_bio_PUBKEY_ex;
  PEM_write_PUBKEY := Load_PEM_write_PUBKEY;
  PEM_write_PUBKEY_ex := Load_PEM_write_PUBKEY_ex;
  PEM_write_bio_PrivateKey_traditional := Load_PEM_write_bio_PrivateKey_traditional;
  PEM_write_bio_PKCS8PrivateKey_nid := Load_PEM_write_bio_PKCS8PrivateKey_nid;
  PEM_write_bio_PKCS8PrivateKey := Load_PEM_write_bio_PKCS8PrivateKey;
  i2d_PKCS8PrivateKey_bio := Load_i2d_PKCS8PrivateKey_bio;
  i2d_PKCS8PrivateKey_nid_bio := Load_i2d_PKCS8PrivateKey_nid_bio;
  d2i_PKCS8PrivateKey_bio := Load_d2i_PKCS8PrivateKey_bio;
{$ifndef  OPENSSL_NO_STDIO}
  i2d_PKCS8PrivateKey_fp := Load_i2d_PKCS8PrivateKey_fp;
  i2d_PKCS8PrivateKey_nid_fp := Load_i2d_PKCS8PrivateKey_nid_fp;
  PEM_write_PKCS8PrivateKey_nid := Load_PEM_write_PKCS8PrivateKey_nid;
  d2i_PKCS8PrivateKey_fp := Load_d2i_PKCS8PrivateKey_fp;
  PEM_write_PKCS8PrivateKey := Load_PEM_write_PKCS8PrivateKey;
{$endif} { OPENSSL_NO_STDIO}
  PEM_read_bio_Parameters_ex := Load_PEM_read_bio_Parameters_ex;
  PEM_read_bio_Parameters := Load_PEM_read_bio_Parameters;
  PEM_write_bio_Parameters := Load_PEM_write_bio_Parameters;
  b2i_PrivateKey := Load_b2i_PrivateKey;
  b2i_PublicKey := Load_b2i_PublicKey;
  b2i_PrivateKey_bio := Load_b2i_PrivateKey_bio;
  b2i_PublicKey_bio := Load_b2i_PublicKey_bio;
  i2b_PrivateKey_bio := Load_i2b_PrivateKey_bio;
  i2b_PublicKey_bio := Load_i2b_PublicKey_bio;
  b2i_PVK_bio := Load_b2i_PVK_bio;
  b2i_PVK_bio_ex := Load_b2i_PVK_bio_ex;
  i2b_PVK_bio := Load_i2b_PVK_bio;
  i2b_PVK_bio_ex := Load_i2b_PVK_bio_ex;
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



