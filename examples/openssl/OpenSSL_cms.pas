(* This unit was generated from the source file cms.h2pas 
It should not be modified directly. All changes should be made to cms.h2pas
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


unit OpenSSL_cms;


interface

// Headers for OpenSSL 1.1.1
// cms.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_x509;

type
  CMS_ContentInfo_st = type Pointer;
  CMS_ContentInfo = CMS_ContentInfo_st;
  PCMS_ContentInfo = ^CMS_ContentInfo;
  PPCMS_ContentInfo = ^PCMS_ContentInfo;

  CMS_SignerInfo_st = type Pointer;
  CMS_SignerInfo = CMS_SignerInfo_st;
  PCMS_SignerInfo = ^CMS_SignerInfo;

  CMS_CertificateChoices_st = type Pointer;
  CMS_CertificateChoices = CMS_CertificateChoices_st;
  PCMS_CertificateChoices = ^CMS_CertificateChoices;

  CMS_RevocationInfoChoice_st = type Pointer;
  CMS_RevocationInfoChoice = CMS_RevocationInfoChoice_st;
  PCMS_RevocationInfoChoice = ^CMS_RevocationInfoChoice;

  CMS_RecipientInfo_st = type Pointer;
  CMS_RecipientInfo = CMS_RecipientInfo_st;
  PCMS_RecipientInfo = ^CMS_RecipientInfo;
  PPCMS_RecipientInfo = ^PCMS_RecipientInfo;

  CMS_ReceiptRequest_st = type Pointer;
  CMS_ReceiptRequest = CMS_ReceiptRequest_st;
  PCMS_ReceiptRequest = ^CMS_ReceiptRequest;
  PPCMS_ReceiptRequest = ^PCMS_ReceiptRequest;

  CMS_Receipt_st = type Pointer;
  CMS_Receipt = CMS_Receipt_st;
  PCMS_Receipt = ^CMS_Receipt;

  CMS_RecipientEncryptedKey_st = type Pointer;
  CMS_RecipientEncryptedKey = CMS_RecipientEncryptedKey_st;
  PCMS_RecipientEncryptedKey = ^CMS_RecipientEncryptedKey;

  CMS_OtherKeyAttribute_st = type Pointer;
  CMS_OtherKeyAttribute = CMS_OtherKeyAttribute_st;
  PCMS_OtherKeyAttribute = ^CMS_OtherKeyAttribute;
  PPCMS_OtherKeyAttribute = ^PCMS_OtherKeyAttribute;

//DEFINE_STACK_OF(CMS_SignerInfo)
//DEFINE_STACK_OF(CMS_RecipientEncryptedKey)
//DEFINE_STACK_OF(CMS_RecipientInfo)
//DEFINE_STACK_OF(CMS_RevocationInfoChoice)
//DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)
//DECLARE_ASN1_FUNCTIONS(CMS_ReceiptRequest)
//DECLARE_ASN1_PRINT_FUNCTION(CMS_ContentInfo)

const
  CMS_SIGNERINFO_ISSUER_SERIAL    = 0;
  CMS_SIGNERINFO_KEYIDENTIFIER    = 1;

  CMS_RECIPINFO_NONE              = -1;
  CMS_RECIPINFO_TRANS             = 0;
  CMS_RECIPINFO_AGREE             = 1;
  CMS_RECIPINFO_KEK               = 2;
  CMS_RECIPINFO_PASS              = 3;
  CMS_RECIPINFO_OTHER             = 4;

// S/MIME related flags /

  CMS_TEXT                        = $1;
  CMS_NOCERTS                     = $2;
  CMS_NO_CONTENT_VERIFY           = $4;
  CMS_NO_ATTR_VERIFY              = $8;
  CMS_NOSIGS                      = (CMS_NO_CONTENT_VERIFY or CMS_NO_ATTR_VERIFY);
  CMS_NOINTERN                    = $10;
  CMS_NO_SIGNER_CERT_VERIFY       = $20;
  CMS_NOVERIFY                    = $20;
  CMS_DETACHED                    = $40;
  CMS_BINARY                      = $80;
  CMS_NOATTR                      = $100;
  CMS_NOSMIMECAP                  = $200;
  CMS_NOOLDMIMETYPE               = $400;
  CMS_CRLFEOL                     = $800;
  CMS_STREAM_CONST                = $1000;
  CMS_NOCRL                       = $2000;
  CMS_PARTIAL                     = $4000;
  CMS_REUSE_DIGEST                = $8000;
  CMS_USE_KEYID                   = $10000;
  CMS_DEBUG_DECRYPT               = $20000;
  CMS_KEY_PARAM                   = $40000;
  CMS_ASCIICRLF                   = $80000;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CMS_get0_type}
{$EXTERNALSYM CMS_dataInit}
{$EXTERNALSYM CMS_dataFinal}
{$EXTERNALSYM CMS_get0_content}
{$EXTERNALSYM CMS_is_detached}
{$EXTERNALSYM CMS_set_detached}
{$EXTERNALSYM CMS_stream}
{$EXTERNALSYM d2i_CMS_bio}
{$EXTERNALSYM i2d_CMS_bio}
{$EXTERNALSYM BIO_new_CMS}
{$EXTERNALSYM i2d_CMS_bio_stream}
{$EXTERNALSYM PEM_write_bio_CMS_stream}
{$EXTERNALSYM SMIME_read_CMS}
{$EXTERNALSYM SMIME_write_CMS}
{$EXTERNALSYM CMS_final}
{$EXTERNALSYM CMS_data}
{$EXTERNALSYM CMS_data_create}
{$EXTERNALSYM CMS_digest_verify}
{$EXTERNALSYM CMS_digest_create}
{$EXTERNALSYM CMS_EncryptedData_decrypt}
{$EXTERNALSYM CMS_EncryptedData_encrypt}
{$EXTERNALSYM CMS_EncryptedData_set1_key}
{$EXTERNALSYM CMS_decrypt}
{$EXTERNALSYM CMS_decrypt_set1_pkey}
{$EXTERNALSYM CMS_decrypt_set1_key}
{$EXTERNALSYM CMS_decrypt_set1_password}
{$EXTERNALSYM CMS_RecipientInfo_type}
{$EXTERNALSYM CMS_RecipientInfo_get0_pkey_ctx}
{$EXTERNALSYM CMS_EnvelopedData_create}
{$EXTERNALSYM CMS_add1_recipient_cert}
{$EXTERNALSYM CMS_RecipientInfo_set0_pkey}
{$EXTERNALSYM CMS_RecipientInfo_ktri_cert_cmp}
{$EXTERNALSYM CMS_RecipientInfo_ktri_get0_algs}
{$EXTERNALSYM CMS_RecipientInfo_ktri_get0_signer_id}
{$EXTERNALSYM CMS_add0_recipient_key}
{$EXTERNALSYM CMS_RecipientInfo_kekri_get0_id}
{$EXTERNALSYM CMS_RecipientInfo_set0_key}
{$EXTERNALSYM CMS_RecipientInfo_kekri_id_cmp}
{$EXTERNALSYM CMS_RecipientInfo_set0_password}
{$EXTERNALSYM CMS_add0_recipient_password}
{$EXTERNALSYM CMS_RecipientInfo_decrypt}
{$EXTERNALSYM CMS_RecipientInfo_encrypt}
{$EXTERNALSYM CMS_uncompress}
{$EXTERNALSYM CMS_compress}
{$EXTERNALSYM CMS_set1_eContentType}
{$EXTERNALSYM CMS_get0_eContentType}
{$EXTERNALSYM CMS_add0_CertificateChoices}
{$EXTERNALSYM CMS_add0_cert}
{$EXTERNALSYM CMS_add1_cert}
{$EXTERNALSYM CMS_add0_RevocationInfoChoice}
{$EXTERNALSYM CMS_add0_crl}
{$EXTERNALSYM CMS_add1_crl}
{$EXTERNALSYM CMS_SignedData_init}
{$EXTERNALSYM CMS_add1_signer}
{$EXTERNALSYM CMS_SignerInfo_get0_pkey_ctx}
{$EXTERNALSYM CMS_SignerInfo_get0_md_ctx}
{$EXTERNALSYM CMS_SignerInfo_set1_signer_cert}
{$EXTERNALSYM CMS_SignerInfo_get0_signer_id}
{$EXTERNALSYM CMS_SignerInfo_cert_cmp}
{$EXTERNALSYM CMS_SignerInfo_get0_algs}
{$EXTERNALSYM CMS_SignerInfo_get0_signature}
{$EXTERNALSYM CMS_SignerInfo_sign}
{$EXTERNALSYM CMS_SignerInfo_verify}
{$EXTERNALSYM CMS_SignerInfo_verify_content}
{$EXTERNALSYM CMS_signed_get_attr_count}
{$EXTERNALSYM CMS_signed_get_attr_by_NID}
{$EXTERNALSYM CMS_signed_get_attr_by_OBJ}
{$EXTERNALSYM CMS_signed_get_attr}
{$EXTERNALSYM CMS_signed_delete_attr}
{$EXTERNALSYM CMS_signed_add1_attr}
{$EXTERNALSYM CMS_signed_add1_attr_by_OBJ}
{$EXTERNALSYM CMS_signed_add1_attr_by_NID}
{$EXTERNALSYM CMS_signed_add1_attr_by_txt}
{$EXTERNALSYM CMS_signed_get0_data_by_OBJ}
{$EXTERNALSYM CMS_unsigned_get_attr_count}
{$EXTERNALSYM CMS_unsigned_get_attr_by_NID}
{$EXTERNALSYM CMS_unsigned_get_attr_by_OBJ}
{$EXTERNALSYM CMS_unsigned_get_attr}
{$EXTERNALSYM CMS_unsigned_delete_attr}
{$EXTERNALSYM CMS_unsigned_add1_attr}
{$EXTERNALSYM CMS_unsigned_add1_attr_by_OBJ}
{$EXTERNALSYM CMS_unsigned_add1_attr_by_NID}
{$EXTERNALSYM CMS_unsigned_add1_attr_by_txt}
{$EXTERNALSYM CMS_unsigned_get0_data_by_OBJ}
{$EXTERNALSYM CMS_get1_ReceiptRequest}
{$EXTERNALSYM CMS_add1_ReceiptRequest}
{$EXTERNALSYM CMS_RecipientInfo_kari_get0_orig_id}
{$EXTERNALSYM CMS_RecipientInfo_kari_orig_id_cmp}
{$EXTERNALSYM CMS_RecipientEncryptedKey_get0_id}
{$EXTERNALSYM CMS_RecipientEncryptedKey_cert_cmp}
{$EXTERNALSYM CMS_RecipientInfo_kari_set0_pkey}
{$EXTERNALSYM CMS_RecipientInfo_kari_get0_ctx}
{$EXTERNALSYM CMS_RecipientInfo_kari_decrypt}
{$EXTERNALSYM CMS_SharedInfo_encode}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CMS_get0_type(const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl; external CLibCrypto;
function CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl; external CLibCrypto;
function CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl; external CLibCrypto;
function CMS_is_detached(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_set_detached(cms: PCMS_ContentInfo; detached: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_stream(cms: PCMS_ContentInfo; boundary: PPPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl; external CLibCrypto;
function i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_new_CMS(out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl; external CLibCrypto;
function i2d_CMS_bio_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_CMS_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl; external CLibCrypto;
function SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_data(cms: PCMS_ContentInfo; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_data_create(in_: PBIO; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_digest_create(in_: PBIO; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; const key: PByte; keylen: TOpenSSL_C_SIZET; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_EncryptedData_encrypt(in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PByte; keylen: TOpenSSL_C_SIZET; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function CMS_EnvelopedData_create(const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TOpenSSL_C_UINT): PCMS_RecipientInfo; cdecl; external CLibCrypto;
function CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_ktri_get0_signer_id(ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TOpenSSL_C_INT; key: PByte; keylen: TOpenSSL_C_SIZET; id: PByte; idlen: TOpenSSL_C_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TOpenSSL_C_INT; wrap_nid: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl; external CLibCrypto;
function CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_compress(in_: PBIO; comp_nid: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_set1_eContentType(cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl; external CLibCrypto;
function CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl; external CLibCrypto;
function CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl; external CLibCrypto;
function CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignedData_init(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_SignerInfo; cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl; external CLibCrypto;
procedure CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509); cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function CMS_SignerInfo_sign(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignerInfo_verify(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_signed_delete_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_signed_add1_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SharedInfo_encode(pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  CMS_get0_type: function (const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;
  CMS_dataInit: function (cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl = nil;
  CMS_dataFinal: function (cms: PCMS_ContentInfo; bio: PBIO): TOpenSSL_C_INT; cdecl = nil;
  CMS_get0_content: function (cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl = nil;
  CMS_is_detached: function (cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_set_detached: function (cms: PCMS_ContentInfo; detached: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_stream: function (cms: PCMS_ContentInfo; boundary: PPPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_CMS_bio: function (bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl = nil;
  i2d_CMS_bio: function (bp: PBIO; cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl = nil;
  BIO_new_CMS: function (out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl = nil;
  i2d_CMS_bio_stream: function (out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_CMS_stream: function (out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SMIME_read_CMS: function (bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl = nil;
  SMIME_write_CMS: function (bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_final: function (cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  CMS_data: function (cms: PCMS_ContentInfo; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  CMS_data_create: function (in_: PBIO; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = nil;
  CMS_digest_verify: function (cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  CMS_digest_create: function (in_: PBIO; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = nil;
  CMS_EncryptedData_decrypt: function (cms: PCMS_ContentInfo; const key: PByte; keylen: TOpenSSL_C_SIZET; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  CMS_EncryptedData_encrypt: function (in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = nil;
  CMS_EncryptedData_set1_key: function (cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  CMS_decrypt: function (cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  CMS_decrypt_set1_pkey: function (cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  CMS_decrypt_set1_key: function (cms: PCMS_ContentInfo; key: PByte; keylen: TOpenSSL_C_SIZET; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  CMS_decrypt_set1_password: function (cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_type: function (ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_get0_pkey_ctx: function (ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl = nil;
  CMS_EnvelopedData_create: function (const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl = nil;
  CMS_add1_recipient_cert: function (cms: PCMS_ContentInfo; recip: PX509; flags: TOpenSSL_C_UINT): PCMS_RecipientInfo; cdecl = nil;
  CMS_RecipientInfo_set0_pkey: function (ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_ktri_cert_cmp: function (ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_ktri_get0_algs: function (ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_ktri_get0_signer_id: function (ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  CMS_add0_recipient_key: function (cms: PCMS_ContentInfo; nid: TOpenSSL_C_INT; key: PByte; keylen: TOpenSSL_C_SIZET; id: PByte; idlen: TOpenSSL_C_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl = nil;
  CMS_RecipientInfo_kekri_get0_id: function (ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_set0_key: function (ri: PCMS_RecipientInfo; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_kekri_id_cmp: function (ri: PCMS_RecipientInfo; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_set0_password: function (ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl = nil;
  CMS_add0_recipient_password: function (cms: PCMS_ContentInfo; iter: TOpenSSL_C_INT; wrap_nid: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl = nil;
  CMS_RecipientInfo_decrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_encrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_uncompress: function (cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  CMS_compress: function (in_: PBIO; comp_nid: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = nil;
  CMS_set1_eContentType: function (cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  CMS_get0_eContentType: function (cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;
  CMS_add0_CertificateChoices: function (cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl = nil;
  CMS_add0_cert: function (cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  CMS_add1_cert: function (cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  CMS_add0_RevocationInfoChoice: function (cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl = nil;
  CMS_add0_crl: function (cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  CMS_add1_crl: function (cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  CMS_SignedData_init: function (cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_add1_signer: function (cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_SignerInfo; cdecl = nil;
  CMS_SignerInfo_get0_pkey_ctx: function (si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl = nil;
  CMS_SignerInfo_get0_md_ctx: function (si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl = nil;
  CMS_SignerInfo_set1_signer_cert: procedure (si: PCMS_SignerInfo; signer: PX509); cdecl = nil;
  CMS_SignerInfo_get0_signer_id: function (si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  CMS_SignerInfo_cert_cmp: function (si: PCMS_SignerInfo; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  CMS_SignerInfo_get0_algs: procedure (si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl = nil;
  CMS_SignerInfo_get0_signature: function (si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl = nil;
  CMS_SignerInfo_sign: function (si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_SignerInfo_verify: function (si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_SignerInfo_verify_content: function (si: PCMS_SignerInfo; chain: PBIO): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_get_attr_count: function (const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_get_attr_by_NID: function (const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_get_attr_by_OBJ: function (const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_get_attr: function (const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_signed_delete_attr: function (const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_signed_add1_attr: function (si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_add1_attr_by_OBJ: function (si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_add1_attr_by_NID: function (si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_add1_attr_by_txt: function (si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_signed_get0_data_by_OBJ: function (si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CMS_unsigned_get_attr_count: function (const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = nil;
  CMS_unsigned_get_attr_by_NID: function (const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_unsigned_get_attr_by_OBJ: function (const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_unsigned_get_attr: function (const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_unsigned_delete_attr: function (si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_unsigned_add1_attr: function (si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = nil;
  CMS_unsigned_add1_attr_by_OBJ: function (si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_unsigned_add1_attr_by_NID: function (si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_unsigned_add1_attr_by_txt: function (si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CMS_unsigned_get0_data_by_OBJ: function (si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CMS_get1_ReceiptRequest: function (si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl = nil;
  CMS_add1_ReceiptRequest: function (si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_kari_get0_orig_id: function (ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_kari_orig_id_cmp: function (ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientEncryptedKey_get0_id: function (rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientEncryptedKey_cert_cmp: function (rek: PCMS_RecipientEncryptedKey; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_kari_set0_pkey: function (ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  CMS_RecipientInfo_kari_get0_ctx: function (ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl = nil;
  CMS_RecipientInfo_kari_decrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TOpenSSL_C_INT; cdecl = nil;
  CMS_SharedInfo_encode: function (pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
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
function ERROR_CMS_get0_type(const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get0_type');
end;

function ERROR_CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_dataInit');
end;

function ERROR_CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_dataFinal');
end;

function ERROR_CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get0_content');
end;

function ERROR_CMS_is_detached(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_is_detached');
end;

function ERROR_CMS_set_detached(cms: PCMS_ContentInfo; detached: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_set_detached');
end;

function ERROR_CMS_stream(cms: PCMS_ContentInfo; boundary: PPPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_stream');
end;

function ERROR_d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_CMS_bio');
end;

function ERROR_i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_CMS_bio');
end;

function ERROR_BIO_new_CMS(out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_CMS');
end;

function ERROR_i2d_CMS_bio_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_CMS_bio_stream');
end;

function ERROR_PEM_write_bio_CMS_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_CMS_stream');
end;

function ERROR_SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_read_CMS');
end;

function ERROR_SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_write_CMS');
end;

function ERROR_CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_final');
end;

function ERROR_CMS_data(cms: PCMS_ContentInfo; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_data');
end;

function ERROR_CMS_data_create(in_: PBIO; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_data_create');
end;

function ERROR_CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_digest_verify');
end;

function ERROR_CMS_digest_create(in_: PBIO; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_digest_create');
end;

function ERROR_CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; const key: PByte; keylen: TOpenSSL_C_SIZET; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EncryptedData_decrypt');
end;

function ERROR_CMS_EncryptedData_encrypt(in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EncryptedData_encrypt');
end;

function ERROR_CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EncryptedData_set1_key');
end;

function ERROR_CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt');
end;

function ERROR_CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt_set1_pkey');
end;

function ERROR_CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PByte; keylen: TOpenSSL_C_SIZET; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt_set1_key');
end;

function ERROR_CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt_set1_password');
end;

function ERROR_CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_type');
end;

function ERROR_CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_get0_pkey_ctx');
end;

function ERROR_CMS_EnvelopedData_create(const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EnvelopedData_create');
end;

function ERROR_CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TOpenSSL_C_UINT): PCMS_RecipientInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_recipient_cert');
end;

function ERROR_CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_set0_pkey');
end;

function ERROR_CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_ktri_cert_cmp');
end;

function ERROR_CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_ktri_get0_algs');
end;

function ERROR_CMS_RecipientInfo_ktri_get0_signer_id(ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_ktri_get0_signer_id');
end;

function ERROR_CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TOpenSSL_C_INT; key: PByte; keylen: TOpenSSL_C_SIZET; id: PByte; idlen: TOpenSSL_C_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_recipient_key');
end;

function ERROR_CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kekri_get0_id');
end;

function ERROR_CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_set0_key');
end;

function ERROR_CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kekri_id_cmp');
end;

function ERROR_CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_set0_password');
end;

function ERROR_CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TOpenSSL_C_INT; wrap_nid: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_recipient_password');
end;

function ERROR_CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_decrypt');
end;

function ERROR_CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_encrypt');
end;

function ERROR_CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_uncompress');
end;

function ERROR_CMS_compress(in_: PBIO; comp_nid: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_compress');
end;

function ERROR_CMS_set1_eContentType(cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_set1_eContentType');
end;

function ERROR_CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get0_eContentType');
end;

function ERROR_CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_CertificateChoices');
end;

function ERROR_CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_cert');
end;

function ERROR_CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_cert');
end;

function ERROR_CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_RevocationInfoChoice');
end;

function ERROR_CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_crl');
end;

function ERROR_CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_crl');
end;

function ERROR_CMS_SignedData_init(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignedData_init');
end;

function ERROR_CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_SignerInfo; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_signer');
end;

function ERROR_CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_pkey_ctx');
end;

function ERROR_CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_md_ctx');
end;

procedure ERROR_CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_set1_signer_cert');
end;

function ERROR_CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_signer_id');
end;

function ERROR_CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_cert_cmp');
end;

procedure ERROR_CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_algs');
end;

function ERROR_CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_signature');
end;

function ERROR_CMS_SignerInfo_sign(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_sign');
end;

function ERROR_CMS_SignerInfo_verify(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_verify');
end;

function ERROR_CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_verify_content');
end;

function ERROR_CMS_signed_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr_count');
end;

function ERROR_CMS_signed_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr_by_NID');
end;

function ERROR_CMS_signed_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr_by_OBJ');
end;

function ERROR_CMS_signed_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr');
end;

function ERROR_CMS_signed_delete_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_delete_attr');
end;

function ERROR_CMS_signed_add1_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr');
end;

function ERROR_CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr_by_OBJ');
end;

function ERROR_CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr_by_NID');
end;

function ERROR_CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr_by_txt');
end;

function ERROR_CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get0_data_by_OBJ');
end;

function ERROR_CMS_unsigned_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr_count');
end;

function ERROR_CMS_unsigned_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr_by_NID');
end;

function ERROR_CMS_unsigned_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr_by_OBJ');
end;

function ERROR_CMS_unsigned_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr');
end;

function ERROR_CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_delete_attr');
end;

function ERROR_CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr');
end;

function ERROR_CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr_by_OBJ');
end;

function ERROR_CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr_by_NID');
end;

function ERROR_CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr_by_txt');
end;

function ERROR_CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get0_data_by_OBJ');
end;

function ERROR_CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get1_ReceiptRequest');
end;

function ERROR_CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_ReceiptRequest');
end;

function ERROR_CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_get0_orig_id');
end;

function ERROR_CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_orig_id_cmp');
end;

function ERROR_CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientEncryptedKey_get0_id');
end;

function ERROR_CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientEncryptedKey_cert_cmp');
end;

function ERROR_CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_set0_pkey');
end;

function ERROR_CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_get0_ctx');
end;

function ERROR_CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_decrypt');
end;

function ERROR_CMS_SharedInfo_encode(pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SharedInfo_encode');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  CMS_get0_type := LoadLibCryptoFunction('CMS_get0_type');
  FuncLoadError := not assigned(CMS_get0_type);
  if FuncLoadError then
  begin
    CMS_get0_type :=  @ERROR_CMS_get0_type;
  end;

  CMS_dataInit := LoadLibCryptoFunction('CMS_dataInit');
  FuncLoadError := not assigned(CMS_dataInit);
  if FuncLoadError then
  begin
    CMS_dataInit :=  @ERROR_CMS_dataInit;
  end;

  CMS_dataFinal := LoadLibCryptoFunction('CMS_dataFinal');
  FuncLoadError := not assigned(CMS_dataFinal);
  if FuncLoadError then
  begin
    CMS_dataFinal :=  @ERROR_CMS_dataFinal;
  end;

  CMS_get0_content := LoadLibCryptoFunction('CMS_get0_content');
  FuncLoadError := not assigned(CMS_get0_content);
  if FuncLoadError then
  begin
    CMS_get0_content :=  @ERROR_CMS_get0_content;
  end;

  CMS_is_detached := LoadLibCryptoFunction('CMS_is_detached');
  FuncLoadError := not assigned(CMS_is_detached);
  if FuncLoadError then
  begin
    CMS_is_detached :=  @ERROR_CMS_is_detached;
  end;

  CMS_set_detached := LoadLibCryptoFunction('CMS_set_detached');
  FuncLoadError := not assigned(CMS_set_detached);
  if FuncLoadError then
  begin
    CMS_set_detached :=  @ERROR_CMS_set_detached;
  end;

  CMS_stream := LoadLibCryptoFunction('CMS_stream');
  FuncLoadError := not assigned(CMS_stream);
  if FuncLoadError then
  begin
    CMS_stream :=  @ERROR_CMS_stream;
  end;

  d2i_CMS_bio := LoadLibCryptoFunction('d2i_CMS_bio');
  FuncLoadError := not assigned(d2i_CMS_bio);
  if FuncLoadError then
  begin
    d2i_CMS_bio :=  @ERROR_d2i_CMS_bio;
  end;

  i2d_CMS_bio := LoadLibCryptoFunction('i2d_CMS_bio');
  FuncLoadError := not assigned(i2d_CMS_bio);
  if FuncLoadError then
  begin
    i2d_CMS_bio :=  @ERROR_i2d_CMS_bio;
  end;

  BIO_new_CMS := LoadLibCryptoFunction('BIO_new_CMS');
  FuncLoadError := not assigned(BIO_new_CMS);
  if FuncLoadError then
  begin
    BIO_new_CMS :=  @ERROR_BIO_new_CMS;
  end;

  i2d_CMS_bio_stream := LoadLibCryptoFunction('i2d_CMS_bio_stream');
  FuncLoadError := not assigned(i2d_CMS_bio_stream);
  if FuncLoadError then
  begin
    i2d_CMS_bio_stream :=  @ERROR_i2d_CMS_bio_stream;
  end;

  PEM_write_bio_CMS_stream := LoadLibCryptoFunction('PEM_write_bio_CMS_stream');
  FuncLoadError := not assigned(PEM_write_bio_CMS_stream);
  if FuncLoadError then
  begin
    PEM_write_bio_CMS_stream :=  @ERROR_PEM_write_bio_CMS_stream;
  end;

  SMIME_read_CMS := LoadLibCryptoFunction('SMIME_read_CMS');
  FuncLoadError := not assigned(SMIME_read_CMS);
  if FuncLoadError then
  begin
    SMIME_read_CMS :=  @ERROR_SMIME_read_CMS;
  end;

  SMIME_write_CMS := LoadLibCryptoFunction('SMIME_write_CMS');
  FuncLoadError := not assigned(SMIME_write_CMS);
  if FuncLoadError then
  begin
    SMIME_write_CMS :=  @ERROR_SMIME_write_CMS;
  end;

  CMS_final := LoadLibCryptoFunction('CMS_final');
  FuncLoadError := not assigned(CMS_final);
  if FuncLoadError then
  begin
    CMS_final :=  @ERROR_CMS_final;
  end;

  CMS_data := LoadLibCryptoFunction('CMS_data');
  FuncLoadError := not assigned(CMS_data);
  if FuncLoadError then
  begin
    CMS_data :=  @ERROR_CMS_data;
  end;

  CMS_data_create := LoadLibCryptoFunction('CMS_data_create');
  FuncLoadError := not assigned(CMS_data_create);
  if FuncLoadError then
  begin
    CMS_data_create :=  @ERROR_CMS_data_create;
  end;

  CMS_digest_verify := LoadLibCryptoFunction('CMS_digest_verify');
  FuncLoadError := not assigned(CMS_digest_verify);
  if FuncLoadError then
  begin
    CMS_digest_verify :=  @ERROR_CMS_digest_verify;
  end;

  CMS_digest_create := LoadLibCryptoFunction('CMS_digest_create');
  FuncLoadError := not assigned(CMS_digest_create);
  if FuncLoadError then
  begin
    CMS_digest_create :=  @ERROR_CMS_digest_create;
  end;

  CMS_EncryptedData_decrypt := LoadLibCryptoFunction('CMS_EncryptedData_decrypt');
  FuncLoadError := not assigned(CMS_EncryptedData_decrypt);
  if FuncLoadError then
  begin
    CMS_EncryptedData_decrypt :=  @ERROR_CMS_EncryptedData_decrypt;
  end;

  CMS_EncryptedData_encrypt := LoadLibCryptoFunction('CMS_EncryptedData_encrypt');
  FuncLoadError := not assigned(CMS_EncryptedData_encrypt);
  if FuncLoadError then
  begin
    CMS_EncryptedData_encrypt :=  @ERROR_CMS_EncryptedData_encrypt;
  end;

  CMS_EncryptedData_set1_key := LoadLibCryptoFunction('CMS_EncryptedData_set1_key');
  FuncLoadError := not assigned(CMS_EncryptedData_set1_key);
  if FuncLoadError then
  begin
    CMS_EncryptedData_set1_key :=  @ERROR_CMS_EncryptedData_set1_key;
  end;

  CMS_decrypt := LoadLibCryptoFunction('CMS_decrypt');
  FuncLoadError := not assigned(CMS_decrypt);
  if FuncLoadError then
  begin
    CMS_decrypt :=  @ERROR_CMS_decrypt;
  end;

  CMS_decrypt_set1_pkey := LoadLibCryptoFunction('CMS_decrypt_set1_pkey');
  FuncLoadError := not assigned(CMS_decrypt_set1_pkey);
  if FuncLoadError then
  begin
    CMS_decrypt_set1_pkey :=  @ERROR_CMS_decrypt_set1_pkey;
  end;

  CMS_decrypt_set1_key := LoadLibCryptoFunction('CMS_decrypt_set1_key');
  FuncLoadError := not assigned(CMS_decrypt_set1_key);
  if FuncLoadError then
  begin
    CMS_decrypt_set1_key :=  @ERROR_CMS_decrypt_set1_key;
  end;

  CMS_decrypt_set1_password := LoadLibCryptoFunction('CMS_decrypt_set1_password');
  FuncLoadError := not assigned(CMS_decrypt_set1_password);
  if FuncLoadError then
  begin
    CMS_decrypt_set1_password :=  @ERROR_CMS_decrypt_set1_password;
  end;

  CMS_RecipientInfo_type := LoadLibCryptoFunction('CMS_RecipientInfo_type');
  FuncLoadError := not assigned(CMS_RecipientInfo_type);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_type :=  @ERROR_CMS_RecipientInfo_type;
  end;

  CMS_RecipientInfo_get0_pkey_ctx := LoadLibCryptoFunction('CMS_RecipientInfo_get0_pkey_ctx');
  FuncLoadError := not assigned(CMS_RecipientInfo_get0_pkey_ctx);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_get0_pkey_ctx :=  @ERROR_CMS_RecipientInfo_get0_pkey_ctx;
  end;

  CMS_EnvelopedData_create := LoadLibCryptoFunction('CMS_EnvelopedData_create');
  FuncLoadError := not assigned(CMS_EnvelopedData_create);
  if FuncLoadError then
  begin
    CMS_EnvelopedData_create :=  @ERROR_CMS_EnvelopedData_create;
  end;

  CMS_add1_recipient_cert := LoadLibCryptoFunction('CMS_add1_recipient_cert');
  FuncLoadError := not assigned(CMS_add1_recipient_cert);
  if FuncLoadError then
  begin
    CMS_add1_recipient_cert :=  @ERROR_CMS_add1_recipient_cert;
  end;

  CMS_RecipientInfo_set0_pkey := LoadLibCryptoFunction('CMS_RecipientInfo_set0_pkey');
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_pkey);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_set0_pkey :=  @ERROR_CMS_RecipientInfo_set0_pkey;
  end;

  CMS_RecipientInfo_ktri_cert_cmp := LoadLibCryptoFunction('CMS_RecipientInfo_ktri_cert_cmp');
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_cert_cmp);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_ktri_cert_cmp :=  @ERROR_CMS_RecipientInfo_ktri_cert_cmp;
  end;

  CMS_RecipientInfo_ktri_get0_algs := LoadLibCryptoFunction('CMS_RecipientInfo_ktri_get0_algs');
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_get0_algs);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_ktri_get0_algs :=  @ERROR_CMS_RecipientInfo_ktri_get0_algs;
  end;

  CMS_RecipientInfo_ktri_get0_signer_id := LoadLibCryptoFunction('CMS_RecipientInfo_ktri_get0_signer_id');
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_get0_signer_id);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_ktri_get0_signer_id :=  @ERROR_CMS_RecipientInfo_ktri_get0_signer_id;
  end;

  CMS_add0_recipient_key := LoadLibCryptoFunction('CMS_add0_recipient_key');
  FuncLoadError := not assigned(CMS_add0_recipient_key);
  if FuncLoadError then
  begin
    CMS_add0_recipient_key :=  @ERROR_CMS_add0_recipient_key;
  end;

  CMS_RecipientInfo_kekri_get0_id := LoadLibCryptoFunction('CMS_RecipientInfo_kekri_get0_id');
  FuncLoadError := not assigned(CMS_RecipientInfo_kekri_get0_id);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_kekri_get0_id :=  @ERROR_CMS_RecipientInfo_kekri_get0_id;
  end;

  CMS_RecipientInfo_set0_key := LoadLibCryptoFunction('CMS_RecipientInfo_set0_key');
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_key);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_set0_key :=  @ERROR_CMS_RecipientInfo_set0_key;
  end;

  CMS_RecipientInfo_kekri_id_cmp := LoadLibCryptoFunction('CMS_RecipientInfo_kekri_id_cmp');
  FuncLoadError := not assigned(CMS_RecipientInfo_kekri_id_cmp);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_kekri_id_cmp :=  @ERROR_CMS_RecipientInfo_kekri_id_cmp;
  end;

  CMS_RecipientInfo_set0_password := LoadLibCryptoFunction('CMS_RecipientInfo_set0_password');
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_password);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_set0_password :=  @ERROR_CMS_RecipientInfo_set0_password;
  end;

  CMS_add0_recipient_password := LoadLibCryptoFunction('CMS_add0_recipient_password');
  FuncLoadError := not assigned(CMS_add0_recipient_password);
  if FuncLoadError then
  begin
    CMS_add0_recipient_password :=  @ERROR_CMS_add0_recipient_password;
  end;

  CMS_RecipientInfo_decrypt := LoadLibCryptoFunction('CMS_RecipientInfo_decrypt');
  FuncLoadError := not assigned(CMS_RecipientInfo_decrypt);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_decrypt :=  @ERROR_CMS_RecipientInfo_decrypt;
  end;

  CMS_RecipientInfo_encrypt := LoadLibCryptoFunction('CMS_RecipientInfo_encrypt');
  FuncLoadError := not assigned(CMS_RecipientInfo_encrypt);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_encrypt :=  @ERROR_CMS_RecipientInfo_encrypt;
  end;

  CMS_uncompress := LoadLibCryptoFunction('CMS_uncompress');
  FuncLoadError := not assigned(CMS_uncompress);
  if FuncLoadError then
  begin
    CMS_uncompress :=  @ERROR_CMS_uncompress;
  end;

  CMS_compress := LoadLibCryptoFunction('CMS_compress');
  FuncLoadError := not assigned(CMS_compress);
  if FuncLoadError then
  begin
    CMS_compress :=  @ERROR_CMS_compress;
  end;

  CMS_set1_eContentType := LoadLibCryptoFunction('CMS_set1_eContentType');
  FuncLoadError := not assigned(CMS_set1_eContentType);
  if FuncLoadError then
  begin
    CMS_set1_eContentType :=  @ERROR_CMS_set1_eContentType;
  end;

  CMS_get0_eContentType := LoadLibCryptoFunction('CMS_get0_eContentType');
  FuncLoadError := not assigned(CMS_get0_eContentType);
  if FuncLoadError then
  begin
    CMS_get0_eContentType :=  @ERROR_CMS_get0_eContentType;
  end;

  CMS_add0_CertificateChoices := LoadLibCryptoFunction('CMS_add0_CertificateChoices');
  FuncLoadError := not assigned(CMS_add0_CertificateChoices);
  if FuncLoadError then
  begin
    CMS_add0_CertificateChoices :=  @ERROR_CMS_add0_CertificateChoices;
  end;

  CMS_add0_cert := LoadLibCryptoFunction('CMS_add0_cert');
  FuncLoadError := not assigned(CMS_add0_cert);
  if FuncLoadError then
  begin
    CMS_add0_cert :=  @ERROR_CMS_add0_cert;
  end;

  CMS_add1_cert := LoadLibCryptoFunction('CMS_add1_cert');
  FuncLoadError := not assigned(CMS_add1_cert);
  if FuncLoadError then
  begin
    CMS_add1_cert :=  @ERROR_CMS_add1_cert;
  end;

  CMS_add0_RevocationInfoChoice := LoadLibCryptoFunction('CMS_add0_RevocationInfoChoice');
  FuncLoadError := not assigned(CMS_add0_RevocationInfoChoice);
  if FuncLoadError then
  begin
    CMS_add0_RevocationInfoChoice :=  @ERROR_CMS_add0_RevocationInfoChoice;
  end;

  CMS_add0_crl := LoadLibCryptoFunction('CMS_add0_crl');
  FuncLoadError := not assigned(CMS_add0_crl);
  if FuncLoadError then
  begin
    CMS_add0_crl :=  @ERROR_CMS_add0_crl;
  end;

  CMS_add1_crl := LoadLibCryptoFunction('CMS_add1_crl');
  FuncLoadError := not assigned(CMS_add1_crl);
  if FuncLoadError then
  begin
    CMS_add1_crl :=  @ERROR_CMS_add1_crl;
  end;

  CMS_SignedData_init := LoadLibCryptoFunction('CMS_SignedData_init');
  FuncLoadError := not assigned(CMS_SignedData_init);
  if FuncLoadError then
  begin
    CMS_SignedData_init :=  @ERROR_CMS_SignedData_init;
  end;

  CMS_add1_signer := LoadLibCryptoFunction('CMS_add1_signer');
  FuncLoadError := not assigned(CMS_add1_signer);
  if FuncLoadError then
  begin
    CMS_add1_signer :=  @ERROR_CMS_add1_signer;
  end;

  CMS_SignerInfo_get0_pkey_ctx := LoadLibCryptoFunction('CMS_SignerInfo_get0_pkey_ctx');
  FuncLoadError := not assigned(CMS_SignerInfo_get0_pkey_ctx);
  if FuncLoadError then
  begin
    CMS_SignerInfo_get0_pkey_ctx :=  @ERROR_CMS_SignerInfo_get0_pkey_ctx;
  end;

  CMS_SignerInfo_get0_md_ctx := LoadLibCryptoFunction('CMS_SignerInfo_get0_md_ctx');
  FuncLoadError := not assigned(CMS_SignerInfo_get0_md_ctx);
  if FuncLoadError then
  begin
    CMS_SignerInfo_get0_md_ctx :=  @ERROR_CMS_SignerInfo_get0_md_ctx;
  end;

  CMS_SignerInfo_set1_signer_cert := LoadLibCryptoFunction('CMS_SignerInfo_set1_signer_cert');
  FuncLoadError := not assigned(CMS_SignerInfo_set1_signer_cert);
  if FuncLoadError then
  begin
    CMS_SignerInfo_set1_signer_cert :=  @ERROR_CMS_SignerInfo_set1_signer_cert;
  end;

  CMS_SignerInfo_get0_signer_id := LoadLibCryptoFunction('CMS_SignerInfo_get0_signer_id');
  FuncLoadError := not assigned(CMS_SignerInfo_get0_signer_id);
  if FuncLoadError then
  begin
    CMS_SignerInfo_get0_signer_id :=  @ERROR_CMS_SignerInfo_get0_signer_id;
  end;

  CMS_SignerInfo_cert_cmp := LoadLibCryptoFunction('CMS_SignerInfo_cert_cmp');
  FuncLoadError := not assigned(CMS_SignerInfo_cert_cmp);
  if FuncLoadError then
  begin
    CMS_SignerInfo_cert_cmp :=  @ERROR_CMS_SignerInfo_cert_cmp;
  end;

  CMS_SignerInfo_get0_algs := LoadLibCryptoFunction('CMS_SignerInfo_get0_algs');
  FuncLoadError := not assigned(CMS_SignerInfo_get0_algs);
  if FuncLoadError then
  begin
    CMS_SignerInfo_get0_algs :=  @ERROR_CMS_SignerInfo_get0_algs;
  end;

  CMS_SignerInfo_get0_signature := LoadLibCryptoFunction('CMS_SignerInfo_get0_signature');
  FuncLoadError := not assigned(CMS_SignerInfo_get0_signature);
  if FuncLoadError then
  begin
    CMS_SignerInfo_get0_signature :=  @ERROR_CMS_SignerInfo_get0_signature;
  end;

  CMS_SignerInfo_sign := LoadLibCryptoFunction('CMS_SignerInfo_sign');
  FuncLoadError := not assigned(CMS_SignerInfo_sign);
  if FuncLoadError then
  begin
    CMS_SignerInfo_sign :=  @ERROR_CMS_SignerInfo_sign;
  end;

  CMS_SignerInfo_verify := LoadLibCryptoFunction('CMS_SignerInfo_verify');
  FuncLoadError := not assigned(CMS_SignerInfo_verify);
  if FuncLoadError then
  begin
    CMS_SignerInfo_verify :=  @ERROR_CMS_SignerInfo_verify;
  end;

  CMS_SignerInfo_verify_content := LoadLibCryptoFunction('CMS_SignerInfo_verify_content');
  FuncLoadError := not assigned(CMS_SignerInfo_verify_content);
  if FuncLoadError then
  begin
    CMS_SignerInfo_verify_content :=  @ERROR_CMS_SignerInfo_verify_content;
  end;

  CMS_signed_get_attr_count := LoadLibCryptoFunction('CMS_signed_get_attr_count');
  FuncLoadError := not assigned(CMS_signed_get_attr_count);
  if FuncLoadError then
  begin
    CMS_signed_get_attr_count :=  @ERROR_CMS_signed_get_attr_count;
  end;

  CMS_signed_get_attr_by_NID := LoadLibCryptoFunction('CMS_signed_get_attr_by_NID');
  FuncLoadError := not assigned(CMS_signed_get_attr_by_NID);
  if FuncLoadError then
  begin
    CMS_signed_get_attr_by_NID :=  @ERROR_CMS_signed_get_attr_by_NID;
  end;

  CMS_signed_get_attr_by_OBJ := LoadLibCryptoFunction('CMS_signed_get_attr_by_OBJ');
  FuncLoadError := not assigned(CMS_signed_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    CMS_signed_get_attr_by_OBJ :=  @ERROR_CMS_signed_get_attr_by_OBJ;
  end;

  CMS_signed_get_attr := LoadLibCryptoFunction('CMS_signed_get_attr');
  FuncLoadError := not assigned(CMS_signed_get_attr);
  if FuncLoadError then
  begin
    CMS_signed_get_attr :=  @ERROR_CMS_signed_get_attr;
  end;

  CMS_signed_delete_attr := LoadLibCryptoFunction('CMS_signed_delete_attr');
  FuncLoadError := not assigned(CMS_signed_delete_attr);
  if FuncLoadError then
  begin
    CMS_signed_delete_attr :=  @ERROR_CMS_signed_delete_attr;
  end;

  CMS_signed_add1_attr := LoadLibCryptoFunction('CMS_signed_add1_attr');
  FuncLoadError := not assigned(CMS_signed_add1_attr);
  if FuncLoadError then
  begin
    CMS_signed_add1_attr :=  @ERROR_CMS_signed_add1_attr;
  end;

  CMS_signed_add1_attr_by_OBJ := LoadLibCryptoFunction('CMS_signed_add1_attr_by_OBJ');
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    CMS_signed_add1_attr_by_OBJ :=  @ERROR_CMS_signed_add1_attr_by_OBJ;
  end;

  CMS_signed_add1_attr_by_NID := LoadLibCryptoFunction('CMS_signed_add1_attr_by_NID');
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_NID);
  if FuncLoadError then
  begin
    CMS_signed_add1_attr_by_NID :=  @ERROR_CMS_signed_add1_attr_by_NID;
  end;

  CMS_signed_add1_attr_by_txt := LoadLibCryptoFunction('CMS_signed_add1_attr_by_txt');
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_txt);
  if FuncLoadError then
  begin
    CMS_signed_add1_attr_by_txt :=  @ERROR_CMS_signed_add1_attr_by_txt;
  end;

  CMS_signed_get0_data_by_OBJ := LoadLibCryptoFunction('CMS_signed_get0_data_by_OBJ');
  FuncLoadError := not assigned(CMS_signed_get0_data_by_OBJ);
  if FuncLoadError then
  begin
    CMS_signed_get0_data_by_OBJ :=  @ERROR_CMS_signed_get0_data_by_OBJ;
  end;

  CMS_unsigned_get_attr_count := LoadLibCryptoFunction('CMS_unsigned_get_attr_count');
  FuncLoadError := not assigned(CMS_unsigned_get_attr_count);
  if FuncLoadError then
  begin
    CMS_unsigned_get_attr_count :=  @ERROR_CMS_unsigned_get_attr_count;
  end;

  CMS_unsigned_get_attr_by_NID := LoadLibCryptoFunction('CMS_unsigned_get_attr_by_NID');
  FuncLoadError := not assigned(CMS_unsigned_get_attr_by_NID);
  if FuncLoadError then
  begin
    CMS_unsigned_get_attr_by_NID :=  @ERROR_CMS_unsigned_get_attr_by_NID;
  end;

  CMS_unsigned_get_attr_by_OBJ := LoadLibCryptoFunction('CMS_unsigned_get_attr_by_OBJ');
  FuncLoadError := not assigned(CMS_unsigned_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    CMS_unsigned_get_attr_by_OBJ :=  @ERROR_CMS_unsigned_get_attr_by_OBJ;
  end;

  CMS_unsigned_get_attr := LoadLibCryptoFunction('CMS_unsigned_get_attr');
  FuncLoadError := not assigned(CMS_unsigned_get_attr);
  if FuncLoadError then
  begin
    CMS_unsigned_get_attr :=  @ERROR_CMS_unsigned_get_attr;
  end;

  CMS_unsigned_delete_attr := LoadLibCryptoFunction('CMS_unsigned_delete_attr');
  FuncLoadError := not assigned(CMS_unsigned_delete_attr);
  if FuncLoadError then
  begin
    CMS_unsigned_delete_attr :=  @ERROR_CMS_unsigned_delete_attr;
  end;

  CMS_unsigned_add1_attr := LoadLibCryptoFunction('CMS_unsigned_add1_attr');
  FuncLoadError := not assigned(CMS_unsigned_add1_attr);
  if FuncLoadError then
  begin
    CMS_unsigned_add1_attr :=  @ERROR_CMS_unsigned_add1_attr;
  end;

  CMS_unsigned_add1_attr_by_OBJ := LoadLibCryptoFunction('CMS_unsigned_add1_attr_by_OBJ');
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    CMS_unsigned_add1_attr_by_OBJ :=  @ERROR_CMS_unsigned_add1_attr_by_OBJ;
  end;

  CMS_unsigned_add1_attr_by_NID := LoadLibCryptoFunction('CMS_unsigned_add1_attr_by_NID');
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_NID);
  if FuncLoadError then
  begin
    CMS_unsigned_add1_attr_by_NID :=  @ERROR_CMS_unsigned_add1_attr_by_NID;
  end;

  CMS_unsigned_add1_attr_by_txt := LoadLibCryptoFunction('CMS_unsigned_add1_attr_by_txt');
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_txt);
  if FuncLoadError then
  begin
    CMS_unsigned_add1_attr_by_txt :=  @ERROR_CMS_unsigned_add1_attr_by_txt;
  end;

  CMS_unsigned_get0_data_by_OBJ := LoadLibCryptoFunction('CMS_unsigned_get0_data_by_OBJ');
  FuncLoadError := not assigned(CMS_unsigned_get0_data_by_OBJ);
  if FuncLoadError then
  begin
    CMS_unsigned_get0_data_by_OBJ :=  @ERROR_CMS_unsigned_get0_data_by_OBJ;
  end;

  CMS_get1_ReceiptRequest := LoadLibCryptoFunction('CMS_get1_ReceiptRequest');
  FuncLoadError := not assigned(CMS_get1_ReceiptRequest);
  if FuncLoadError then
  begin
    CMS_get1_ReceiptRequest :=  @ERROR_CMS_get1_ReceiptRequest;
  end;

  CMS_add1_ReceiptRequest := LoadLibCryptoFunction('CMS_add1_ReceiptRequest');
  FuncLoadError := not assigned(CMS_add1_ReceiptRequest);
  if FuncLoadError then
  begin
    CMS_add1_ReceiptRequest :=  @ERROR_CMS_add1_ReceiptRequest;
  end;

  CMS_RecipientInfo_kari_get0_orig_id := LoadLibCryptoFunction('CMS_RecipientInfo_kari_get0_orig_id');
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_orig_id);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_kari_get0_orig_id :=  @ERROR_CMS_RecipientInfo_kari_get0_orig_id;
  end;

  CMS_RecipientInfo_kari_orig_id_cmp := LoadLibCryptoFunction('CMS_RecipientInfo_kari_orig_id_cmp');
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_orig_id_cmp);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_kari_orig_id_cmp :=  @ERROR_CMS_RecipientInfo_kari_orig_id_cmp;
  end;

  CMS_RecipientEncryptedKey_get0_id := LoadLibCryptoFunction('CMS_RecipientEncryptedKey_get0_id');
  FuncLoadError := not assigned(CMS_RecipientEncryptedKey_get0_id);
  if FuncLoadError then
  begin
    CMS_RecipientEncryptedKey_get0_id :=  @ERROR_CMS_RecipientEncryptedKey_get0_id;
  end;

  CMS_RecipientEncryptedKey_cert_cmp := LoadLibCryptoFunction('CMS_RecipientEncryptedKey_cert_cmp');
  FuncLoadError := not assigned(CMS_RecipientEncryptedKey_cert_cmp);
  if FuncLoadError then
  begin
    CMS_RecipientEncryptedKey_cert_cmp :=  @ERROR_CMS_RecipientEncryptedKey_cert_cmp;
  end;

  CMS_RecipientInfo_kari_set0_pkey := LoadLibCryptoFunction('CMS_RecipientInfo_kari_set0_pkey');
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_set0_pkey);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_kari_set0_pkey :=  @ERROR_CMS_RecipientInfo_kari_set0_pkey;
  end;

  CMS_RecipientInfo_kari_get0_ctx := LoadLibCryptoFunction('CMS_RecipientInfo_kari_get0_ctx');
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_ctx);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_kari_get0_ctx :=  @ERROR_CMS_RecipientInfo_kari_get0_ctx;
  end;

  CMS_RecipientInfo_kari_decrypt := LoadLibCryptoFunction('CMS_RecipientInfo_kari_decrypt');
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_decrypt);
  if FuncLoadError then
  begin
    CMS_RecipientInfo_kari_decrypt :=  @ERROR_CMS_RecipientInfo_kari_decrypt;
  end;

  CMS_SharedInfo_encode := LoadLibCryptoFunction('CMS_SharedInfo_encode');
  FuncLoadError := not assigned(CMS_SharedInfo_encode);
  if FuncLoadError then
  begin
    CMS_SharedInfo_encode :=  @ERROR_CMS_SharedInfo_encode;
  end;

end;

procedure UnLoad;
begin
  CMS_get0_type := nil;
  CMS_dataInit := nil;
  CMS_dataFinal := nil;
  CMS_get0_content := nil;
  CMS_is_detached := nil;
  CMS_set_detached := nil;
  CMS_stream := nil;
  d2i_CMS_bio := nil;
  i2d_CMS_bio := nil;
  BIO_new_CMS := nil;
  i2d_CMS_bio_stream := nil;
  PEM_write_bio_CMS_stream := nil;
  SMIME_read_CMS := nil;
  SMIME_write_CMS := nil;
  CMS_final := nil;
  CMS_data := nil;
  CMS_data_create := nil;
  CMS_digest_verify := nil;
  CMS_digest_create := nil;
  CMS_EncryptedData_decrypt := nil;
  CMS_EncryptedData_encrypt := nil;
  CMS_EncryptedData_set1_key := nil;
  CMS_decrypt := nil;
  CMS_decrypt_set1_pkey := nil;
  CMS_decrypt_set1_key := nil;
  CMS_decrypt_set1_password := nil;
  CMS_RecipientInfo_type := nil;
  CMS_RecipientInfo_get0_pkey_ctx := nil;
  CMS_EnvelopedData_create := nil;
  CMS_add1_recipient_cert := nil;
  CMS_RecipientInfo_set0_pkey := nil;
  CMS_RecipientInfo_ktri_cert_cmp := nil;
  CMS_RecipientInfo_ktri_get0_algs := nil;
  CMS_RecipientInfo_ktri_get0_signer_id := nil;
  CMS_add0_recipient_key := nil;
  CMS_RecipientInfo_kekri_get0_id := nil;
  CMS_RecipientInfo_set0_key := nil;
  CMS_RecipientInfo_kekri_id_cmp := nil;
  CMS_RecipientInfo_set0_password := nil;
  CMS_add0_recipient_password := nil;
  CMS_RecipientInfo_decrypt := nil;
  CMS_RecipientInfo_encrypt := nil;
  CMS_uncompress := nil;
  CMS_compress := nil;
  CMS_set1_eContentType := nil;
  CMS_get0_eContentType := nil;
  CMS_add0_CertificateChoices := nil;
  CMS_add0_cert := nil;
  CMS_add1_cert := nil;
  CMS_add0_RevocationInfoChoice := nil;
  CMS_add0_crl := nil;
  CMS_add1_crl := nil;
  CMS_SignedData_init := nil;
  CMS_add1_signer := nil;
  CMS_SignerInfo_get0_pkey_ctx := nil;
  CMS_SignerInfo_get0_md_ctx := nil;
  CMS_SignerInfo_set1_signer_cert := nil;
  CMS_SignerInfo_get0_signer_id := nil;
  CMS_SignerInfo_cert_cmp := nil;
  CMS_SignerInfo_get0_algs := nil;
  CMS_SignerInfo_get0_signature := nil;
  CMS_SignerInfo_sign := nil;
  CMS_SignerInfo_verify := nil;
  CMS_SignerInfo_verify_content := nil;
  CMS_signed_get_attr_count := nil;
  CMS_signed_get_attr_by_NID := nil;
  CMS_signed_get_attr_by_OBJ := nil;
  CMS_signed_get_attr := nil;
  CMS_signed_delete_attr := nil;
  CMS_signed_add1_attr := nil;
  CMS_signed_add1_attr_by_OBJ := nil;
  CMS_signed_add1_attr_by_NID := nil;
  CMS_signed_add1_attr_by_txt := nil;
  CMS_signed_get0_data_by_OBJ := nil;
  CMS_unsigned_get_attr_count := nil;
  CMS_unsigned_get_attr_by_NID := nil;
  CMS_unsigned_get_attr_by_OBJ := nil;
  CMS_unsigned_get_attr := nil;
  CMS_unsigned_delete_attr := nil;
  CMS_unsigned_add1_attr := nil;
  CMS_unsigned_add1_attr_by_OBJ := nil;
  CMS_unsigned_add1_attr_by_NID := nil;
  CMS_unsigned_add1_attr_by_txt := nil;
  CMS_unsigned_get0_data_by_OBJ := nil;
  CMS_get1_ReceiptRequest := nil;
  CMS_add1_ReceiptRequest := nil;
  CMS_RecipientInfo_kari_get0_orig_id := nil;
  CMS_RecipientInfo_kari_orig_id_cmp := nil;
  CMS_RecipientEncryptedKey_get0_id := nil;
  CMS_RecipientEncryptedKey_cert_cmp := nil;
  CMS_RecipientInfo_kari_set0_pkey := nil;
  CMS_RecipientInfo_kari_get0_ctx := nil;
  CMS_RecipientInfo_kari_decrypt := nil;
  CMS_SharedInfo_encode := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
