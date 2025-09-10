(* This unit was generated from the source file pkcs12.h2pas 
It should not be modified directly. All changes should be made to pkcs12.h2pas
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


unit OpenSSL_pkcs12;


interface

// Headers for OpenSSL 1.1.1
// pkcs12.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_pkcs7,
  OpenSSL_x509;

const
  PKCS12_KEY_ID = 1;
  PKCS12_IV_ID = 2;
  PKCS12_MAC_ID = 3;

  ///* Default iteration count */
  //# ifndef PKCS12_DEFAULT_ITER
  //#  define PKCS12_DEFAULT_ITER     PKCS5_DEFAULT_ITER
  //# endif
  
  PKCS12_MAC_KEY_LENGTH = 20;

  PKCS12_SALT_LEN = 8;

  ///* It's not clear if these are actually needed... */
  //# define PKCS12_key_gen PKCS12_key_gen_utf8
  //# define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8

  (* MS key usage constants *)
  KEY_EX  = $10;
  KEY_SIG = $80;

  PKCS12_ERROR    = 0;
  PKCS12_OK       = 1;
  
type
  PKCS12_MAC_DATA_st = type Pointer;
  PKCS12_MAC_DATA = PKCS12_MAC_DATA_st;
  PPKCS12_MAC_DATA = ^PKCS12_MAC_DATA;
  PPPKCS12_MAC_DATA = ^PPKCS12_MAC_DATA;

  PKCS12_st = type Pointer;
  PKCS12 = PKCS12_st;
  PPKCS12 = ^PKCS12;
  PPPKCS12 = ^PPKCS12;

  PKCS12_SAFEBAG_st = type Pointer;
  PKCS12_SAFEBAG = PKCS12_SAFEBAG_st;
  PPKCS12_SAFEBAG = ^PKCS12_SAFEBAG;
  PPPKCS12_SAFEBAG = ^PPKCS12_SAFEBAG;

//  DEFINE_STACK_OF(PKCS12_SAFEBAG)

  pkcs12_bag_st = type Pointer;
  PKCS12_BAGS = pkcs12_bag_st;
  PPKCS12_BAGS = ^PKCS12_BAGS;
  PPPKCS12_BAGS = ^PPKCS12_BAGS;

  //ASN1_TYPE *PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, TOpenSSL_C_INT attr_nid);
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM PKCS12_mac_present}
{$EXTERNALSYM PKCS12_get0_mac}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_attr}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_type}
{$EXTERNALSYM PKCS12_SAFEBAG_get_nid}
{$EXTERNALSYM PKCS12_SAFEBAG_get_bag_nid}
{$EXTERNALSYM PKCS12_SAFEBAG_get1_cert}
{$EXTERNALSYM PKCS12_SAFEBAG_get1_crl}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_p8inf}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_pkcs8}
{$EXTERNALSYM PKCS12_SAFEBAG_create_cert}
{$EXTERNALSYM PKCS12_SAFEBAG_create_crl}
{$EXTERNALSYM PKCS12_SAFEBAG_create0_p8inf}
{$EXTERNALSYM PKCS12_SAFEBAG_create0_pkcs8}
{$EXTERNALSYM PKCS12_SAFEBAG_create_pkcs8_encrypt}
{$EXTERNALSYM PKCS12_item_pack_safebag}
{$EXTERNALSYM PKCS8_decrypt}
{$EXTERNALSYM PKCS12_decrypt_skey}
{$EXTERNALSYM PKCS8_encrypt}
{$EXTERNALSYM PKCS8_set0_pbe}
{$EXTERNALSYM PKCS12_add_localkeyid}
{$EXTERNALSYM PKCS12_add_friendlyname_asc}
{$EXTERNALSYM PKCS12_add_friendlyname_utf8}
{$EXTERNALSYM PKCS12_add_CSPName_asc}
{$EXTERNALSYM PKCS12_add_friendlyname_uni}
{$EXTERNALSYM PKCS8_add_keyusage}
{$EXTERNALSYM PKCS12_get_friendlyname}
{$EXTERNALSYM PKCS12_pbe_crypt}
{$EXTERNALSYM PKCS12_item_decrypt_d2i}
{$EXTERNALSYM PKCS12_item_i2d_encrypt}
{$EXTERNALSYM PKCS12_init}
{$EXTERNALSYM PKCS12_key_gen_asc}
{$EXTERNALSYM PKCS12_key_gen_uni}
{$EXTERNALSYM PKCS12_key_gen_utf8}
{$EXTERNALSYM PKCS12_PBE_keyivgen}
{$EXTERNALSYM PKCS12_gen_mac}
{$EXTERNALSYM PKCS12_verify_mac}
{$EXTERNALSYM PKCS12_set_mac}
{$EXTERNALSYM PKCS12_setup_mac}
{$EXTERNALSYM OPENSSL_asc2uni}
{$EXTERNALSYM OPENSSL_uni2asc}
{$EXTERNALSYM OPENSSL_utf82uni}
{$EXTERNALSYM OPENSSL_uni2utf8}
{$EXTERNALSYM PKCS12_new}
{$EXTERNALSYM PKCS12_free}
{$EXTERNALSYM d2i_PKCS12}
{$EXTERNALSYM i2d_PKCS12}
{$EXTERNALSYM PKCS12_it}
{$EXTERNALSYM PKCS12_MAC_DATA_new}
{$EXTERNALSYM PKCS12_MAC_DATA_free}
{$EXTERNALSYM d2i_PKCS12_MAC_DATA}
{$EXTERNALSYM i2d_PKCS12_MAC_DATA}
{$EXTERNALSYM PKCS12_MAC_DATA_it}
{$EXTERNALSYM PKCS12_SAFEBAG_new}
{$EXTERNALSYM PKCS12_SAFEBAG_free}
{$EXTERNALSYM d2i_PKCS12_SAFEBAG}
{$EXTERNALSYM i2d_PKCS12_SAFEBAG}
{$EXTERNALSYM PKCS12_SAFEBAG_it}
{$EXTERNALSYM PKCS12_BAGS_new}
{$EXTERNALSYM PKCS12_BAGS_free}
{$EXTERNALSYM d2i_PKCS12_BAGS}
{$EXTERNALSYM i2d_PKCS12_BAGS}
{$EXTERNALSYM PKCS12_BAGS_it}
{$EXTERNALSYM PKCS12_PBE_add}
{$EXTERNALSYM PKCS12_parse}
{$EXTERNALSYM PKCS12_create}
{$EXTERNALSYM i2d_PKCS12_bio}
{$EXTERNALSYM d2i_PKCS12_bio}
{$EXTERNALSYM PKCS12_newpass}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function PKCS12_mac_present(const p12: PPKCS12): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure PKCS12_get0_mac(const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_attr(const bag: PPKCS12_SAFEBAG; attr_nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_type(const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get_bag_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get1_cert(const bag: PPKCS12_SAFEBAG): PX509; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get1_crl(const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_p8inf(const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_pkcs8(const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TOpenSSL_C_INT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_item_pack_safebag(obj: Pointer; const it: PASN1_ITEM; nid1: TOpenSSL_C_INT; nid2: TOpenSSL_C_INT): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS8_decrypt(const p8: PX509_SIG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS12_decrypt_skey(const bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS8_encrypt(pbe_nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl; external CLibCrypto;
function PKCS8_set0_pbe(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl; external CLibCrypto;
function PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl; external CLibCrypto;
function PKCS12_pbe_crypt(const algor: PX509_ALGOR; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const in_: PByte; inlen: TOpenSSL_C_INT; data: PPByte; datalen: POpenSSL_C_INT; en_de: TOpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function PKCS12_item_decrypt_d2i(const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const oct: PASN1_OCTET_STRING; zbuf: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; obj: Pointer; zbuf: TOpenSSL_C_INT): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function PKCS12_init(mode: TOpenSSL_C_INT): PPKCS12; cdecl; external CLibCrypto;
function PKCS12_key_gen_asc(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_key_gen_uni(pass: PByte; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_key_gen_utf8(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_gen_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; mac: PByte; maclen: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_verify_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_set_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_setup_mac(p12: PPKCS12; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OPENSSL_asc2uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function OPENSSL_uni2asc(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OPENSSL_utf82uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function OPENSSL_uni2utf8(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function PKCS12_new: PPKCS12; cdecl; external CLibCrypto;
procedure PKCS12_free(a: PPKCS12); cdecl; external CLibCrypto;
function d2i_PKCS12(a: PPPKCS12; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12; cdecl; external CLibCrypto;
function i2d_PKCS12(a: PPKCS12; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_it: PASN1_ITEM; cdecl; external CLibCrypto;
function PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl; external CLibCrypto;
procedure PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl; external CLibCrypto;
function d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_MAC_DATA; cdecl; external CLibCrypto;
function i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
procedure PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl; external CLibCrypto;
function d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl; external CLibCrypto;
function PKCS12_BAGS_new: PPKCS12_BAGS; cdecl; external CLibCrypto;
procedure PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl; external CLibCrypto;
function d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_BAGS; cdecl; external CLibCrypto;
function i2d_PKCS12_BAGS(a: PPKCS12_BAGS; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_BAGS_it: PASN1_ITEM; cdecl; external CLibCrypto;
procedure PKCS12_PBE_add(v: Pointer); cdecl; external CLibCrypto;
function PKCS12_parse(p12: PPKCS12; const pass: PAnsiChar; out pkey: PEVP_PKEY; out cert: PX509; ca: PPStack_Of_X509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_create(const pass: PAnsiChar; const name: PAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TOpenSSL_C_INT; nid_cert: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; mac_iter: TOpenSSL_C_INT; keytype: TOpenSSL_C_INT): PPKCS12; cdecl; external CLibCrypto;
function i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl; external CLibCrypto;
function PKCS12_newpass(p12: PPKCS12; const oldpass: PAnsiChar; const newpass: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  PKCS12_mac_present: function (const p12: PPKCS12): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_get0_mac: procedure (const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl = nil;
  PKCS12_SAFEBAG_get0_attr: function (const bag: PPKCS12_SAFEBAG; attr_nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl = nil;
  PKCS12_SAFEBAG_get0_type: function (const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl = nil;
  PKCS12_SAFEBAG_get_nid: function (const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_SAFEBAG_get_bag_nid: function (const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_SAFEBAG_get1_cert: function (const bag: PPKCS12_SAFEBAG): PX509; cdecl = nil;
  PKCS12_SAFEBAG_get1_crl: function (const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl = nil;
  PKCS12_SAFEBAG_get0_p8inf: function (const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  PKCS12_SAFEBAG_get0_pkcs8: function (const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl = nil;
  PKCS12_SAFEBAG_create_cert: function (x509: PX509): PPKCS12_SAFEBAG; cdecl = nil;
  PKCS12_SAFEBAG_create_crl: function (crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl = nil;
  PKCS12_SAFEBAG_create0_p8inf: function (p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil;
  PKCS12_SAFEBAG_create0_pkcs8: function (p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl = nil;
  PKCS12_SAFEBAG_create_pkcs8_encrypt: function (pbe_nid: TOpenSSL_C_INT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil;
  PKCS12_item_pack_safebag: function (obj: Pointer; const it: PASN1_ITEM; nid1: TOpenSSL_C_INT; nid2: TOpenSSL_C_INT): PPKCS12_SAFEBAG; cdecl = nil;
  PKCS8_decrypt: function (const p8: PX509_SIG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  PKCS12_decrypt_skey: function (const bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  PKCS8_encrypt: function (pbe_nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl = nil;
  PKCS8_set0_pbe: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl = nil;
  PKCS12_add_localkeyid: function (bag: PPKCS12_SAFEBAG; name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_add_friendlyname_asc: function (bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_add_friendlyname_utf8: function (bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_add_CSPName_asc: function (bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_add_friendlyname_uni: function (bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS8_add_keyusage: function (p8: PPKCS8_PRIV_KEY_INFO; usage: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_get_friendlyname: function (bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl = nil;
  PKCS12_pbe_crypt: function (const algor: PX509_ALGOR; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const in_: PByte; inlen: TOpenSSL_C_INT; data: PPByte; datalen: POpenSSL_C_INT; en_de: TOpenSSL_C_INT): PByte; cdecl = nil;
  PKCS12_item_decrypt_d2i: function (const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const oct: PASN1_OCTET_STRING; zbuf: TOpenSSL_C_INT): Pointer; cdecl = nil;
  PKCS12_item_i2d_encrypt: function (algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; obj: Pointer; zbuf: TOpenSSL_C_INT): PASN1_OCTET_STRING; cdecl = nil;
  PKCS12_init: function (mode: TOpenSSL_C_INT): PPKCS12; cdecl = nil;
  PKCS12_key_gen_asc: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_key_gen_uni: function (pass: PByte; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_key_gen_utf8: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_gen_mac: function (p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; mac: PByte; maclen: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_verify_mac: function (p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_set_mac: function (p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_setup_mac: function (p12: PPKCS12; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  OPENSSL_asc2uni: function (const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl = nil;
  OPENSSL_uni2asc: function (const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  OPENSSL_utf82uni: function (const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl = nil;
  OPENSSL_uni2utf8: function (const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  PKCS12_new: function : PPKCS12; cdecl = nil;
  PKCS12_free: procedure (a: PPKCS12); cdecl = nil;
  d2i_PKCS12: function (a: PPPKCS12; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12; cdecl = nil;
  i2d_PKCS12: function (a: PPKCS12; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_it: function : PASN1_ITEM; cdecl = nil;
  PKCS12_MAC_DATA_new: function : PPKCS12_MAC_DATA; cdecl = nil;
  PKCS12_MAC_DATA_free: procedure (a: PPKCS12_MAC_DATA); cdecl = nil;
  d2i_PKCS12_MAC_DATA: function (a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_MAC_DATA; cdecl = nil;
  i2d_PKCS12_MAC_DATA: function (a: PPKCS12_MAC_DATA; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_MAC_DATA_it: function : PASN1_ITEM; cdecl = nil;
  PKCS12_SAFEBAG_new: function : PPKCS12_SAFEBAG; cdecl = nil;
  PKCS12_SAFEBAG_free: procedure (a: PPKCS12_SAFEBAG); cdecl = nil;
  d2i_PKCS12_SAFEBAG: function (a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_SAFEBAG; cdecl = nil;
  i2d_PKCS12_SAFEBAG: function (a: PPKCS12_SAFEBAG; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_SAFEBAG_it: function : PASN1_ITEM; cdecl = nil;
  PKCS12_BAGS_new: function : PPKCS12_BAGS; cdecl = nil;
  PKCS12_BAGS_free: procedure (a: PPKCS12_BAGS); cdecl = nil;
  d2i_PKCS12_BAGS: function (a: PPPKCS12_BAGS; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_BAGS; cdecl = nil;
  i2d_PKCS12_BAGS: function (a: PPKCS12_BAGS; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_BAGS_it: function : PASN1_ITEM; cdecl = nil;
  PKCS12_PBE_add: procedure (v: Pointer); cdecl = nil;
  PKCS12_parse: function (p12: PPKCS12; const pass: PAnsiChar; out pkey: PEVP_PKEY; out cert: PX509; ca: PPStack_Of_X509): TOpenSSL_C_INT; cdecl = nil;
  PKCS12_create: function (const pass: PAnsiChar; const name: PAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TOpenSSL_C_INT; nid_cert: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; mac_iter: TOpenSSL_C_INT; keytype: TOpenSSL_C_INT): PPKCS12; cdecl = nil;
  i2d_PKCS12_bio: function (bp: PBIO; p12: PPKCS12): TOpenSSL_C_INT; cdecl = nil;
  d2i_PKCS12_bio: function (bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl = nil;
  PKCS12_newpass: function (p12: PPKCS12; const oldpass: PAnsiChar; const newpass: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
{$ENDIF}
const
  PKCS12_mac_present_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_get0_mac_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_attr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_bag_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get1_cert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get1_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_p8inf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_pkcs8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_cert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_p8inf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_pkcs8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_pkcs8_encrypt_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS8_set0_pbe_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_add_friendlyname_utf8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_key_gen_utf8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_utf82uni_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_uni2utf8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function ERROR_PKCS12_mac_present(const p12: PPKCS12): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_mac_present');
end;

procedure ERROR_PKCS12_get0_mac(const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_get0_mac');
end;

function ERROR_PKCS12_SAFEBAG_get0_attr(const bag: PPKCS12_SAFEBAG; attr_nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_attr');
end;

function ERROR_PKCS12_SAFEBAG_get0_type(const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_type');
end;

function ERROR_PKCS12_SAFEBAG_get_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get_nid');
end;

function ERROR_PKCS12_SAFEBAG_get_bag_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get_bag_nid');
end;

function ERROR_PKCS12_SAFEBAG_get1_cert(const bag: PPKCS12_SAFEBAG): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get1_cert');
end;

function ERROR_PKCS12_SAFEBAG_get1_crl(const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get1_crl');
end;

function ERROR_PKCS12_SAFEBAG_get0_p8inf(const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_p8inf');
end;

function ERROR_PKCS12_SAFEBAG_get0_pkcs8(const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_pkcs8');
end;

function ERROR_PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create_cert');
end;

function ERROR_PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create_crl');
end;

function ERROR_PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create0_p8inf');
end;

function ERROR_PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create0_pkcs8');
end;

function ERROR_PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TOpenSSL_C_INT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create_pkcs8_encrypt');
end;

function ERROR_PKCS12_item_pack_safebag(obj: Pointer; const it: PASN1_ITEM; nid1: TOpenSSL_C_INT; nid2: TOpenSSL_C_INT): PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_item_pack_safebag');
end;

function ERROR_PKCS8_decrypt(const p8: PX509_SIG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_decrypt');
end;

function ERROR_PKCS12_decrypt_skey(const bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_decrypt_skey');
end;

function ERROR_PKCS8_encrypt(pbe_nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_encrypt');
end;

function ERROR_PKCS8_set0_pbe(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_set0_pbe');
end;

function ERROR_PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_localkeyid');
end;

function ERROR_PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_friendlyname_asc');
end;

function ERROR_PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_friendlyname_utf8');
end;

function ERROR_PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_CSPName_asc');
end;

function ERROR_PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_friendlyname_uni');
end;

function ERROR_PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_add_keyusage');
end;

function ERROR_PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_get_friendlyname');
end;

function ERROR_PKCS12_pbe_crypt(const algor: PX509_ALGOR; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const in_: PByte; inlen: TOpenSSL_C_INT; data: PPByte; datalen: POpenSSL_C_INT; en_de: TOpenSSL_C_INT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_pbe_crypt');
end;

function ERROR_PKCS12_item_decrypt_d2i(const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const oct: PASN1_OCTET_STRING; zbuf: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_item_decrypt_d2i');
end;

function ERROR_PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; obj: Pointer; zbuf: TOpenSSL_C_INT): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_item_i2d_encrypt');
end;

function ERROR_PKCS12_init(mode: TOpenSSL_C_INT): PPKCS12; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_init');
end;

function ERROR_PKCS12_key_gen_asc(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_key_gen_asc');
end;

function ERROR_PKCS12_key_gen_uni(pass: PByte; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_key_gen_uni');
end;

function ERROR_PKCS12_key_gen_utf8(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_key_gen_utf8');
end;

function ERROR_PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_PBE_keyivgen');
end;

function ERROR_PKCS12_gen_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; mac: PByte; maclen: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_gen_mac');
end;

function ERROR_PKCS12_verify_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_verify_mac');
end;

function ERROR_PKCS12_set_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_set_mac');
end;

function ERROR_PKCS12_setup_mac(p12: PPKCS12; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_setup_mac');
end;

function ERROR_OPENSSL_asc2uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_asc2uni');
end;

function ERROR_OPENSSL_uni2asc(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_uni2asc');
end;

function ERROR_OPENSSL_utf82uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_utf82uni');
end;

function ERROR_OPENSSL_uni2utf8(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_uni2utf8');
end;

function ERROR_PKCS12_new: PPKCS12; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_new');
end;

procedure ERROR_PKCS12_free(a: PPKCS12); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_free');
end;

function ERROR_d2i_PKCS12(a: PPPKCS12; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12');
end;

function ERROR_i2d_PKCS12(a: PPKCS12; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12');
end;

function ERROR_PKCS12_it: PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_it');
end;

function ERROR_PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_MAC_DATA_new');
end;

procedure ERROR_PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_MAC_DATA_free');
end;

function ERROR_d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_MAC_DATA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_MAC_DATA');
end;

function ERROR_i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_MAC_DATA');
end;

function ERROR_PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_MAC_DATA_it');
end;

function ERROR_PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_new');
end;

procedure ERROR_PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_free');
end;

function ERROR_d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_SAFEBAG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_SAFEBAG');
end;

function ERROR_i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_SAFEBAG');
end;

function ERROR_PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_it');
end;

function ERROR_PKCS12_BAGS_new: PPKCS12_BAGS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_BAGS_new');
end;

procedure ERROR_PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_BAGS_free');
end;

function ERROR_d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_BAGS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_BAGS');
end;

function ERROR_i2d_PKCS12_BAGS(a: PPKCS12_BAGS; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_BAGS');
end;

function ERROR_PKCS12_BAGS_it: PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_BAGS_it');
end;

procedure ERROR_PKCS12_PBE_add(v: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_PBE_add');
end;

function ERROR_PKCS12_parse(p12: PPKCS12; const pass: PAnsiChar; out pkey: PEVP_PKEY; out cert: PX509; ca: PPStack_Of_X509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_parse');
end;

function ERROR_PKCS12_create(const pass: PAnsiChar; const name: PAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TOpenSSL_C_INT; nid_cert: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; mac_iter: TOpenSSL_C_INT; keytype: TOpenSSL_C_INT): PPKCS12; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_create');
end;

function ERROR_i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_bio');
end;

function ERROR_d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_bio');
end;

function ERROR_PKCS12_newpass(p12: PPKCS12; const oldpass: PAnsiChar; const newpass: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_newpass');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  PKCS12_mac_present := LoadLibCryptoFunction('PKCS12_mac_present');
  FuncLoadError := not assigned(PKCS12_mac_present);
  if FuncLoadError then
  begin
    PKCS12_mac_present :=  @ERROR_PKCS12_mac_present;
  end;

  PKCS12_get0_mac := LoadLibCryptoFunction('PKCS12_get0_mac');
  FuncLoadError := not assigned(PKCS12_get0_mac);
  if FuncLoadError then
  begin
    PKCS12_get0_mac :=  @ERROR_PKCS12_get0_mac;
  end;

  PKCS12_SAFEBAG_get0_attr := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_attr');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_attr);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get0_attr :=  @ERROR_PKCS12_SAFEBAG_get0_attr;
  end;

  PKCS12_SAFEBAG_get0_type := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_type');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_type);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get0_type :=  @ERROR_PKCS12_SAFEBAG_get0_type;
  end;

  PKCS12_SAFEBAG_get_nid := LoadLibCryptoFunction('PKCS12_SAFEBAG_get_nid');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get_nid);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get_nid :=  @ERROR_PKCS12_SAFEBAG_get_nid;
  end;

  PKCS12_SAFEBAG_get_bag_nid := LoadLibCryptoFunction('PKCS12_SAFEBAG_get_bag_nid');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get_bag_nid);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get_bag_nid :=  @ERROR_PKCS12_SAFEBAG_get_bag_nid;
  end;

  PKCS12_SAFEBAG_get1_cert := LoadLibCryptoFunction('PKCS12_SAFEBAG_get1_cert');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get1_cert);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get1_cert :=  @ERROR_PKCS12_SAFEBAG_get1_cert;
  end;

  PKCS12_SAFEBAG_get1_crl := LoadLibCryptoFunction('PKCS12_SAFEBAG_get1_crl');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get1_crl);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get1_crl :=  @ERROR_PKCS12_SAFEBAG_get1_crl;
  end;

  PKCS12_SAFEBAG_get0_p8inf := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_p8inf');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_p8inf);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get0_p8inf :=  @ERROR_PKCS12_SAFEBAG_get0_p8inf;
  end;

  PKCS12_SAFEBAG_get0_pkcs8 := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_pkcs8');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_pkcs8);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_get0_pkcs8 :=  @ERROR_PKCS12_SAFEBAG_get0_pkcs8;
  end;

  PKCS12_SAFEBAG_create_cert := LoadLibCryptoFunction('PKCS12_SAFEBAG_create_cert');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_cert);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_create_cert :=  @ERROR_PKCS12_SAFEBAG_create_cert;
  end;

  PKCS12_SAFEBAG_create_crl := LoadLibCryptoFunction('PKCS12_SAFEBAG_create_crl');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_crl);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_create_crl :=  @ERROR_PKCS12_SAFEBAG_create_crl;
  end;

  PKCS12_SAFEBAG_create0_p8inf := LoadLibCryptoFunction('PKCS12_SAFEBAG_create0_p8inf');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create0_p8inf);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_create0_p8inf :=  @ERROR_PKCS12_SAFEBAG_create0_p8inf;
  end;

  PKCS12_SAFEBAG_create0_pkcs8 := LoadLibCryptoFunction('PKCS12_SAFEBAG_create0_pkcs8');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create0_pkcs8);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_create0_pkcs8 :=  @ERROR_PKCS12_SAFEBAG_create0_pkcs8;
  end;

  PKCS12_SAFEBAG_create_pkcs8_encrypt := LoadLibCryptoFunction('PKCS12_SAFEBAG_create_pkcs8_encrypt');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_pkcs8_encrypt);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_create_pkcs8_encrypt :=  @ERROR_PKCS12_SAFEBAG_create_pkcs8_encrypt;
  end;

  PKCS12_item_pack_safebag := LoadLibCryptoFunction('PKCS12_item_pack_safebag');
  FuncLoadError := not assigned(PKCS12_item_pack_safebag);
  if FuncLoadError then
  begin
    PKCS12_item_pack_safebag :=  @ERROR_PKCS12_item_pack_safebag;
  end;

  PKCS8_decrypt := LoadLibCryptoFunction('PKCS8_decrypt');
  FuncLoadError := not assigned(PKCS8_decrypt);
  if FuncLoadError then
  begin
    PKCS8_decrypt :=  @ERROR_PKCS8_decrypt;
  end;

  PKCS12_decrypt_skey := LoadLibCryptoFunction('PKCS12_decrypt_skey');
  FuncLoadError := not assigned(PKCS12_decrypt_skey);
  if FuncLoadError then
  begin
    PKCS12_decrypt_skey :=  @ERROR_PKCS12_decrypt_skey;
  end;

  PKCS8_encrypt := LoadLibCryptoFunction('PKCS8_encrypt');
  FuncLoadError := not assigned(PKCS8_encrypt);
  if FuncLoadError then
  begin
    PKCS8_encrypt :=  @ERROR_PKCS8_encrypt;
  end;

  PKCS8_set0_pbe := LoadLibCryptoFunction('PKCS8_set0_pbe');
  FuncLoadError := not assigned(PKCS8_set0_pbe);
  if FuncLoadError then
  begin
    PKCS8_set0_pbe :=  @ERROR_PKCS8_set0_pbe;
  end;

  PKCS12_add_localkeyid := LoadLibCryptoFunction('PKCS12_add_localkeyid');
  FuncLoadError := not assigned(PKCS12_add_localkeyid);
  if FuncLoadError then
  begin
    PKCS12_add_localkeyid :=  @ERROR_PKCS12_add_localkeyid;
  end;

  PKCS12_add_friendlyname_asc := LoadLibCryptoFunction('PKCS12_add_friendlyname_asc');
  FuncLoadError := not assigned(PKCS12_add_friendlyname_asc);
  if FuncLoadError then
  begin
    PKCS12_add_friendlyname_asc :=  @ERROR_PKCS12_add_friendlyname_asc;
  end;

  PKCS12_add_friendlyname_utf8 := LoadLibCryptoFunction('PKCS12_add_friendlyname_utf8');
  FuncLoadError := not assigned(PKCS12_add_friendlyname_utf8);
  if FuncLoadError then
  begin
    PKCS12_add_friendlyname_utf8 :=  @ERROR_PKCS12_add_friendlyname_utf8;
  end;

  PKCS12_add_CSPName_asc := LoadLibCryptoFunction('PKCS12_add_CSPName_asc');
  FuncLoadError := not assigned(PKCS12_add_CSPName_asc);
  if FuncLoadError then
  begin
    PKCS12_add_CSPName_asc :=  @ERROR_PKCS12_add_CSPName_asc;
  end;

  PKCS12_add_friendlyname_uni := LoadLibCryptoFunction('PKCS12_add_friendlyname_uni');
  FuncLoadError := not assigned(PKCS12_add_friendlyname_uni);
  if FuncLoadError then
  begin
    PKCS12_add_friendlyname_uni :=  @ERROR_PKCS12_add_friendlyname_uni;
  end;

  PKCS8_add_keyusage := LoadLibCryptoFunction('PKCS8_add_keyusage');
  FuncLoadError := not assigned(PKCS8_add_keyusage);
  if FuncLoadError then
  begin
    PKCS8_add_keyusage :=  @ERROR_PKCS8_add_keyusage;
  end;

  PKCS12_get_friendlyname := LoadLibCryptoFunction('PKCS12_get_friendlyname');
  FuncLoadError := not assigned(PKCS12_get_friendlyname);
  if FuncLoadError then
  begin
    PKCS12_get_friendlyname :=  @ERROR_PKCS12_get_friendlyname;
  end;

  PKCS12_pbe_crypt := LoadLibCryptoFunction('PKCS12_pbe_crypt');
  FuncLoadError := not assigned(PKCS12_pbe_crypt);
  if FuncLoadError then
  begin
    PKCS12_pbe_crypt :=  @ERROR_PKCS12_pbe_crypt;
  end;

  PKCS12_item_decrypt_d2i := LoadLibCryptoFunction('PKCS12_item_decrypt_d2i');
  FuncLoadError := not assigned(PKCS12_item_decrypt_d2i);
  if FuncLoadError then
  begin
    PKCS12_item_decrypt_d2i :=  @ERROR_PKCS12_item_decrypt_d2i;
  end;

  PKCS12_item_i2d_encrypt := LoadLibCryptoFunction('PKCS12_item_i2d_encrypt');
  FuncLoadError := not assigned(PKCS12_item_i2d_encrypt);
  if FuncLoadError then
  begin
    PKCS12_item_i2d_encrypt :=  @ERROR_PKCS12_item_i2d_encrypt;
  end;

  PKCS12_init := LoadLibCryptoFunction('PKCS12_init');
  FuncLoadError := not assigned(PKCS12_init);
  if FuncLoadError then
  begin
    PKCS12_init :=  @ERROR_PKCS12_init;
  end;

  PKCS12_key_gen_asc := LoadLibCryptoFunction('PKCS12_key_gen_asc');
  FuncLoadError := not assigned(PKCS12_key_gen_asc);
  if FuncLoadError then
  begin
    PKCS12_key_gen_asc :=  @ERROR_PKCS12_key_gen_asc;
  end;

  PKCS12_key_gen_uni := LoadLibCryptoFunction('PKCS12_key_gen_uni');
  FuncLoadError := not assigned(PKCS12_key_gen_uni);
  if FuncLoadError then
  begin
    PKCS12_key_gen_uni :=  @ERROR_PKCS12_key_gen_uni;
  end;

  PKCS12_key_gen_utf8 := LoadLibCryptoFunction('PKCS12_key_gen_utf8');
  FuncLoadError := not assigned(PKCS12_key_gen_utf8);
  if FuncLoadError then
  begin
    PKCS12_key_gen_utf8 :=  @ERROR_PKCS12_key_gen_utf8;
  end;

  PKCS12_PBE_keyivgen := LoadLibCryptoFunction('PKCS12_PBE_keyivgen');
  FuncLoadError := not assigned(PKCS12_PBE_keyivgen);
  if FuncLoadError then
  begin
    PKCS12_PBE_keyivgen :=  @ERROR_PKCS12_PBE_keyivgen;
  end;

  PKCS12_gen_mac := LoadLibCryptoFunction('PKCS12_gen_mac');
  FuncLoadError := not assigned(PKCS12_gen_mac);
  if FuncLoadError then
  begin
    PKCS12_gen_mac :=  @ERROR_PKCS12_gen_mac;
  end;

  PKCS12_verify_mac := LoadLibCryptoFunction('PKCS12_verify_mac');
  FuncLoadError := not assigned(PKCS12_verify_mac);
  if FuncLoadError then
  begin
    PKCS12_verify_mac :=  @ERROR_PKCS12_verify_mac;
  end;

  PKCS12_set_mac := LoadLibCryptoFunction('PKCS12_set_mac');
  FuncLoadError := not assigned(PKCS12_set_mac);
  if FuncLoadError then
  begin
    PKCS12_set_mac :=  @ERROR_PKCS12_set_mac;
  end;

  PKCS12_setup_mac := LoadLibCryptoFunction('PKCS12_setup_mac');
  FuncLoadError := not assigned(PKCS12_setup_mac);
  if FuncLoadError then
  begin
    PKCS12_setup_mac :=  @ERROR_PKCS12_setup_mac;
  end;

  OPENSSL_asc2uni := LoadLibCryptoFunction('OPENSSL_asc2uni');
  FuncLoadError := not assigned(OPENSSL_asc2uni);
  if FuncLoadError then
  begin
    OPENSSL_asc2uni :=  @ERROR_OPENSSL_asc2uni;
  end;

  OPENSSL_uni2asc := LoadLibCryptoFunction('OPENSSL_uni2asc');
  FuncLoadError := not assigned(OPENSSL_uni2asc);
  if FuncLoadError then
  begin
    OPENSSL_uni2asc :=  @ERROR_OPENSSL_uni2asc;
  end;

  OPENSSL_utf82uni := LoadLibCryptoFunction('OPENSSL_utf82uni');
  FuncLoadError := not assigned(OPENSSL_utf82uni);
  if FuncLoadError then
  begin
    OPENSSL_utf82uni :=  @ERROR_OPENSSL_utf82uni;
  end;

  OPENSSL_uni2utf8 := LoadLibCryptoFunction('OPENSSL_uni2utf8');
  FuncLoadError := not assigned(OPENSSL_uni2utf8);
  if FuncLoadError then
  begin
    OPENSSL_uni2utf8 :=  @ERROR_OPENSSL_uni2utf8;
  end;

  PKCS12_new := LoadLibCryptoFunction('PKCS12_new');
  FuncLoadError := not assigned(PKCS12_new);
  if FuncLoadError then
  begin
    PKCS12_new :=  @ERROR_PKCS12_new;
  end;

  PKCS12_free := LoadLibCryptoFunction('PKCS12_free');
  FuncLoadError := not assigned(PKCS12_free);
  if FuncLoadError then
  begin
    PKCS12_free :=  @ERROR_PKCS12_free;
  end;

  d2i_PKCS12 := LoadLibCryptoFunction('d2i_PKCS12');
  FuncLoadError := not assigned(d2i_PKCS12);
  if FuncLoadError then
  begin
    d2i_PKCS12 :=  @ERROR_d2i_PKCS12;
  end;

  i2d_PKCS12 := LoadLibCryptoFunction('i2d_PKCS12');
  FuncLoadError := not assigned(i2d_PKCS12);
  if FuncLoadError then
  begin
    i2d_PKCS12 :=  @ERROR_i2d_PKCS12;
  end;

  PKCS12_it := LoadLibCryptoFunction('PKCS12_it');
  FuncLoadError := not assigned(PKCS12_it);
  if FuncLoadError then
  begin
    PKCS12_it :=  @ERROR_PKCS12_it;
  end;

  PKCS12_MAC_DATA_new := LoadLibCryptoFunction('PKCS12_MAC_DATA_new');
  FuncLoadError := not assigned(PKCS12_MAC_DATA_new);
  if FuncLoadError then
  begin
    PKCS12_MAC_DATA_new :=  @ERROR_PKCS12_MAC_DATA_new;
  end;

  PKCS12_MAC_DATA_free := LoadLibCryptoFunction('PKCS12_MAC_DATA_free');
  FuncLoadError := not assigned(PKCS12_MAC_DATA_free);
  if FuncLoadError then
  begin
    PKCS12_MAC_DATA_free :=  @ERROR_PKCS12_MAC_DATA_free;
  end;

  d2i_PKCS12_MAC_DATA := LoadLibCryptoFunction('d2i_PKCS12_MAC_DATA');
  FuncLoadError := not assigned(d2i_PKCS12_MAC_DATA);
  if FuncLoadError then
  begin
    d2i_PKCS12_MAC_DATA :=  @ERROR_d2i_PKCS12_MAC_DATA;
  end;

  i2d_PKCS12_MAC_DATA := LoadLibCryptoFunction('i2d_PKCS12_MAC_DATA');
  FuncLoadError := not assigned(i2d_PKCS12_MAC_DATA);
  if FuncLoadError then
  begin
    i2d_PKCS12_MAC_DATA :=  @ERROR_i2d_PKCS12_MAC_DATA;
  end;

  PKCS12_MAC_DATA_it := LoadLibCryptoFunction('PKCS12_MAC_DATA_it');
  FuncLoadError := not assigned(PKCS12_MAC_DATA_it);
  if FuncLoadError then
  begin
    PKCS12_MAC_DATA_it :=  @ERROR_PKCS12_MAC_DATA_it;
  end;

  PKCS12_SAFEBAG_new := LoadLibCryptoFunction('PKCS12_SAFEBAG_new');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_new);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_new :=  @ERROR_PKCS12_SAFEBAG_new;
  end;

  PKCS12_SAFEBAG_free := LoadLibCryptoFunction('PKCS12_SAFEBAG_free');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_free);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_free :=  @ERROR_PKCS12_SAFEBAG_free;
  end;

  d2i_PKCS12_SAFEBAG := LoadLibCryptoFunction('d2i_PKCS12_SAFEBAG');
  FuncLoadError := not assigned(d2i_PKCS12_SAFEBAG);
  if FuncLoadError then
  begin
    d2i_PKCS12_SAFEBAG :=  @ERROR_d2i_PKCS12_SAFEBAG;
  end;

  i2d_PKCS12_SAFEBAG := LoadLibCryptoFunction('i2d_PKCS12_SAFEBAG');
  FuncLoadError := not assigned(i2d_PKCS12_SAFEBAG);
  if FuncLoadError then
  begin
    i2d_PKCS12_SAFEBAG :=  @ERROR_i2d_PKCS12_SAFEBAG;
  end;

  PKCS12_SAFEBAG_it := LoadLibCryptoFunction('PKCS12_SAFEBAG_it');
  FuncLoadError := not assigned(PKCS12_SAFEBAG_it);
  if FuncLoadError then
  begin
    PKCS12_SAFEBAG_it :=  @ERROR_PKCS12_SAFEBAG_it;
  end;

  PKCS12_BAGS_new := LoadLibCryptoFunction('PKCS12_BAGS_new');
  FuncLoadError := not assigned(PKCS12_BAGS_new);
  if FuncLoadError then
  begin
    PKCS12_BAGS_new :=  @ERROR_PKCS12_BAGS_new;
  end;

  PKCS12_BAGS_free := LoadLibCryptoFunction('PKCS12_BAGS_free');
  FuncLoadError := not assigned(PKCS12_BAGS_free);
  if FuncLoadError then
  begin
    PKCS12_BAGS_free :=  @ERROR_PKCS12_BAGS_free;
  end;

  d2i_PKCS12_BAGS := LoadLibCryptoFunction('d2i_PKCS12_BAGS');
  FuncLoadError := not assigned(d2i_PKCS12_BAGS);
  if FuncLoadError then
  begin
    d2i_PKCS12_BAGS :=  @ERROR_d2i_PKCS12_BAGS;
  end;

  i2d_PKCS12_BAGS := LoadLibCryptoFunction('i2d_PKCS12_BAGS');
  FuncLoadError := not assigned(i2d_PKCS12_BAGS);
  if FuncLoadError then
  begin
    i2d_PKCS12_BAGS :=  @ERROR_i2d_PKCS12_BAGS;
  end;

  PKCS12_BAGS_it := LoadLibCryptoFunction('PKCS12_BAGS_it');
  FuncLoadError := not assigned(PKCS12_BAGS_it);
  if FuncLoadError then
  begin
    PKCS12_BAGS_it :=  @ERROR_PKCS12_BAGS_it;
  end;

  PKCS12_PBE_add := LoadLibCryptoFunction('PKCS12_PBE_add');
  FuncLoadError := not assigned(PKCS12_PBE_add);
  if FuncLoadError then
  begin
    PKCS12_PBE_add :=  @ERROR_PKCS12_PBE_add;
  end;

  PKCS12_parse := LoadLibCryptoFunction('PKCS12_parse');
  FuncLoadError := not assigned(PKCS12_parse);
  if FuncLoadError then
  begin
    PKCS12_parse :=  @ERROR_PKCS12_parse;
  end;

  PKCS12_create := LoadLibCryptoFunction('PKCS12_create');
  FuncLoadError := not assigned(PKCS12_create);
  if FuncLoadError then
  begin
    PKCS12_create :=  @ERROR_PKCS12_create;
  end;

  i2d_PKCS12_bio := LoadLibCryptoFunction('i2d_PKCS12_bio');
  FuncLoadError := not assigned(i2d_PKCS12_bio);
  if FuncLoadError then
  begin
    i2d_PKCS12_bio :=  @ERROR_i2d_PKCS12_bio;
  end;

  d2i_PKCS12_bio := LoadLibCryptoFunction('d2i_PKCS12_bio');
  FuncLoadError := not assigned(d2i_PKCS12_bio);
  if FuncLoadError then
  begin
    d2i_PKCS12_bio :=  @ERROR_d2i_PKCS12_bio;
  end;

  PKCS12_newpass := LoadLibCryptoFunction('PKCS12_newpass');
  FuncLoadError := not assigned(PKCS12_newpass);
  if FuncLoadError then
  begin
    PKCS12_newpass :=  @ERROR_PKCS12_newpass;
  end;

end;

procedure UnLoad;
begin
  PKCS12_mac_present := nil;
  PKCS12_get0_mac := nil;
  PKCS12_SAFEBAG_get0_attr := nil;
  PKCS12_SAFEBAG_get0_type := nil;
  PKCS12_SAFEBAG_get_nid := nil;
  PKCS12_SAFEBAG_get_bag_nid := nil;
  PKCS12_SAFEBAG_get1_cert := nil;
  PKCS12_SAFEBAG_get1_crl := nil;
  PKCS12_SAFEBAG_get0_p8inf := nil;
  PKCS12_SAFEBAG_get0_pkcs8 := nil;
  PKCS12_SAFEBAG_create_cert := nil;
  PKCS12_SAFEBAG_create_crl := nil;
  PKCS12_SAFEBAG_create0_p8inf := nil;
  PKCS12_SAFEBAG_create0_pkcs8 := nil;
  PKCS12_SAFEBAG_create_pkcs8_encrypt := nil;
  PKCS12_item_pack_safebag := nil;
  PKCS8_decrypt := nil;
  PKCS12_decrypt_skey := nil;
  PKCS8_encrypt := nil;
  PKCS8_set0_pbe := nil;
  PKCS12_add_localkeyid := nil;
  PKCS12_add_friendlyname_asc := nil;
  PKCS12_add_friendlyname_utf8 := nil;
  PKCS12_add_CSPName_asc := nil;
  PKCS12_add_friendlyname_uni := nil;
  PKCS8_add_keyusage := nil;
  PKCS12_get_friendlyname := nil;
  PKCS12_pbe_crypt := nil;
  PKCS12_item_decrypt_d2i := nil;
  PKCS12_item_i2d_encrypt := nil;
  PKCS12_init := nil;
  PKCS12_key_gen_asc := nil;
  PKCS12_key_gen_uni := nil;
  PKCS12_key_gen_utf8 := nil;
  PKCS12_PBE_keyivgen := nil;
  PKCS12_gen_mac := nil;
  PKCS12_verify_mac := nil;
  PKCS12_set_mac := nil;
  PKCS12_setup_mac := nil;
  OPENSSL_asc2uni := nil;
  OPENSSL_uni2asc := nil;
  OPENSSL_utf82uni := nil;
  OPENSSL_uni2utf8 := nil;
  PKCS12_new := nil;
  PKCS12_free := nil;
  d2i_PKCS12 := nil;
  i2d_PKCS12 := nil;
  PKCS12_it := nil;
  PKCS12_MAC_DATA_new := nil;
  PKCS12_MAC_DATA_free := nil;
  d2i_PKCS12_MAC_DATA := nil;
  i2d_PKCS12_MAC_DATA := nil;
  PKCS12_MAC_DATA_it := nil;
  PKCS12_SAFEBAG_new := nil;
  PKCS12_SAFEBAG_free := nil;
  d2i_PKCS12_SAFEBAG := nil;
  i2d_PKCS12_SAFEBAG := nil;
  PKCS12_SAFEBAG_it := nil;
  PKCS12_BAGS_new := nil;
  PKCS12_BAGS_free := nil;
  d2i_PKCS12_BAGS := nil;
  i2d_PKCS12_BAGS := nil;
  PKCS12_BAGS_it := nil;
  PKCS12_PBE_add := nil;
  PKCS12_parse := nil;
  PKCS12_create := nil;
  i2d_PKCS12_bio := nil;
  d2i_PKCS12_bio := nil;
  PKCS12_newpass := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
