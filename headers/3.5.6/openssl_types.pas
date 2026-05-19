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

unit openssl_types;

{
  Generated from OpenSSL 3.5.6 Header File types.h - Tue 19 May 14:28:41 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_types.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2,openssl_safestack;


{* Copyright 2001-2026 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}

{* Unfortunate workaround to avoid symbol conflict with wincrypt.h
* See https://github.com/openssl/openssl/issues/9981
}
{$ifdef _WIN32}
  {$define WINCRYPT_USE_SYMBOL_PREFIX}
  {$undef  X509_NAME}
  {$undef  X509_EXTENSIONS}
  {$undef  PKCS7_SIGNER_INFO}
  {$undef  OCSP_REQUEST}
  {$undef  OCSP_RESPONSE}
{$endif}
{$ifndef  OPENSSL_TYPES_H}
  {$define OPENSSL_TYPES_H}
  {$include openssl_macros.inc}
  {$if  OPENSSL_VERSION_MAJOR >= 4}
{# define  OSSL_FUTURE_CONST const}
  {$else}
    {$define OSSL_FUTURE_CONST}
  {$endif}

type
  {Auto-generated forward references}
  Pasn1_string_st = ^Tasn1_string_st;
  PPasn1_string_st = ^Pasn1_string_st;
  Possl_provider_st = ^TOSSL_PROVIDER;
  PPossl_provider_st = ^Possl_provider_st;
  POSSL_PROVIDER = ^TOSSL_PROVIDER;
  PPOSSL_PROVIDER = ^POSSL_PROVIDER;
  PASN1_INTEGER = ^TASN1_INTEGER;
  PPASN1_INTEGER = ^PASN1_INTEGER;
  {end of auto-generated forward references}

  { This is the base type that holds just about everything :-) }
  { moved from asn1.h }
  Tasn1_string_st = record 
    length: TOpenSSL_C_INT;
    type_: TOpenSSL_C_INT;
    data: Pbyte; 
    {* The value of the following field depends on the type being held.  It
    * is mostly being used for BIT_STRING so if the input data has a
    * non-zero 'unused bits' value, it will be handled correctly
    }
    flags: TOpenSSL_C_INT;
  end;
  Tossl_provider_st = record end;
  TOSSL_PROVIDER = Tossl_provider_st;
  { Provider Object }
  TASN1_INTEGER = Tasn1_string_st;
  {$ifndef  NO_ASN1_TYPEDEFS}

type
  {Auto-generated forward references}
  PASN1_ENUMERATED = ^TASN1_ENUMERATED;
  PPASN1_ENUMERATED = ^PASN1_ENUMERATED;
  PASN1_BIT_STRING = ^TASN1_BIT_STRING;
  PPASN1_BIT_STRING = ^PASN1_BIT_STRING;
  PASN1_OCTET_STRING = ^TASN1_OCTET_STRING;
  PPASN1_OCTET_STRING = ^PASN1_OCTET_STRING;
  PASN1_PRINTABLESTRING = ^TASN1_PRINTABLESTRING;
  PPASN1_PRINTABLESTRING = ^PASN1_PRINTABLESTRING;
  PASN1_T61STRING = ^TASN1_T61STRING;
  PPASN1_T61STRING = ^PASN1_T61STRING;
  PASN1_IA5STRING = ^TASN1_IA5STRING;
  PPASN1_IA5STRING = ^PASN1_IA5STRING;
  PASN1_GENERALSTRING = ^TASN1_GENERALSTRING;
  PPASN1_GENERALSTRING = ^PASN1_GENERALSTRING;
  PASN1_UNIVERSALSTRING = ^TASN1_UNIVERSALSTRING;
  PPASN1_UNIVERSALSTRING = ^PASN1_UNIVERSALSTRING;
  PASN1_BMPSTRING = ^TASN1_BMPSTRING;
  PPASN1_BMPSTRING = ^PASN1_BMPSTRING;
  PASN1_UTCTIME = ^TASN1_UTCTIME;
  PPASN1_UTCTIME = ^PASN1_UTCTIME;
  PASN1_TIME = ^TASN1_TIME;
  PPASN1_TIME = ^PASN1_TIME;
  PASN1_GENERALIZEDTIME = ^TASN1_GENERALIZEDTIME;
  PPASN1_GENERALIZEDTIME = ^PASN1_GENERALIZEDTIME;
  PASN1_VISIBLESTRING = ^TASN1_VISIBLESTRING;
  PPASN1_VISIBLESTRING = ^PASN1_VISIBLESTRING;
  PASN1_UTF8STRING = ^TASN1_UTF8STRING;
  PPASN1_UTF8STRING = ^PASN1_UTF8STRING;
  PASN1_STRING = ^TASN1_STRING;
  PPASN1_STRING = ^PASN1_STRING;
  PASN1_BOOLEAN = ^TASN1_BOOLEAN;
  PPASN1_BOOLEAN = ^PASN1_BOOLEAN;
  PASN1_NULL = ^TASN1_NULL;
  PPASN1_NULL = ^PASN1_NULL;
  {end of auto-generated forward references}

  TASN1_ENUMERATED = Tasn1_string_st;
  TASN1_BIT_STRING = Tasn1_string_st;
  TASN1_OCTET_STRING = Tasn1_string_st;
  TASN1_PRINTABLESTRING = Tasn1_string_st;
  TASN1_T61STRING = Tasn1_string_st;
  TASN1_IA5STRING = Tasn1_string_st;
  TASN1_GENERALSTRING = Tasn1_string_st;
  TASN1_UNIVERSALSTRING = Tasn1_string_st;
  TASN1_BMPSTRING = Tasn1_string_st;
  TASN1_UTCTIME = Tasn1_string_st;
  TASN1_TIME = Tasn1_string_st;
  TASN1_GENERALIZEDTIME = Tasn1_string_st;
  TASN1_VISIBLESTRING = Tasn1_string_st;
  TASN1_UTF8STRING = Tasn1_string_st;
  TASN1_STRING = Tasn1_string_st;
  TASN1_BOOLEAN = TOpenSSL_C_INT;
  TASN1_NULL = TOpenSSL_C_INT;
  {$else}

type
  {Auto-generated forward references}
  PASN1_INTEGER = ^TASN1_INTEGER;
  PPASN1_INTEGER = ^PASN1_INTEGER;
  PASN1_ENUMERATED = ^TASN1_ENUMERATED;
  PPASN1_ENUMERATED = ^PASN1_ENUMERATED;
  PASN1_BIT_STRING = ^TASN1_BIT_STRING;
  PPASN1_BIT_STRING = ^PASN1_BIT_STRING;
  PASN1_OCTET_STRING = ^TASN1_OCTET_STRING;
  PPASN1_OCTET_STRING = ^PASN1_OCTET_STRING;
  PASN1_PRINTABLESTRING = ^TASN1_PRINTABLESTRING;
  PPASN1_PRINTABLESTRING = ^PASN1_PRINTABLESTRING;
  PASN1_T61STRING = ^TASN1_T61STRING;
  PPASN1_T61STRING = ^PASN1_T61STRING;
  PASN1_IA5STRING = ^TASN1_IA5STRING;
  PPASN1_IA5STRING = ^PASN1_IA5STRING;
  PASN1_UTCTIME = ^TASN1_UTCTIME;
  PPASN1_UTCTIME = ^PASN1_UTCTIME;
  PASN1_GENERALIZEDTIME = ^TASN1_GENERALIZEDTIME;
  PPASN1_GENERALIZEDTIME = ^PASN1_GENERALIZEDTIME;
  PASN1_TIME = ^TASN1_TIME;
  PPASN1_TIME = ^PASN1_TIME;
  PASN1_GENERALSTRING = ^TASN1_GENERALSTRING;
  PPASN1_GENERALSTRING = ^PASN1_GENERALSTRING;
  PASN1_UNIVERSALSTRING = ^TASN1_UNIVERSALSTRING;
  PPASN1_UNIVERSALSTRING = ^PASN1_UNIVERSALSTRING;
  PASN1_BMPSTRING = ^TASN1_BMPSTRING;
  PPASN1_BMPSTRING = ^PASN1_BMPSTRING;
  PASN1_VISIBLESTRING = ^TASN1_VISIBLESTRING;
  PPASN1_VISIBLESTRING = ^PASN1_VISIBLESTRING;
  PASN1_UTF8STRING = ^TASN1_UTF8STRING;
  PPASN1_UTF8STRING = ^PASN1_UTF8STRING;
  PASN1_BOOLEAN = ^TASN1_BOOLEAN;
  PPASN1_BOOLEAN = ^PASN1_BOOLEAN;
  PASN1_NULL = ^TASN1_NULL;
  PPASN1_NULL = ^PASN1_NULL;
  {end of auto-generated forward references}

  TASN1_INTEGER = TASN1_STRING;
  TASN1_ENUMERATED = TASN1_STRING;
  TASN1_BIT_STRING = TASN1_STRING;
  TASN1_OCTET_STRING = TASN1_STRING;
  TASN1_PRINTABLESTRING = TASN1_STRING;
  TASN1_T61STRING = TASN1_STRING;
  TASN1_IA5STRING = TASN1_STRING;
  TASN1_UTCTIME = TASN1_STRING;
  TASN1_GENERALIZEDTIME = TASN1_STRING;
  TASN1_TIME = TASN1_STRING;
  TASN1_GENERALSTRING = TASN1_STRING;
  TASN1_UNIVERSALSTRING = TASN1_STRING;
  TASN1_BMPSTRING = TASN1_STRING;
  TASN1_VISIBLESTRING = TASN1_STRING;
  TASN1_UTF8STRING = TASN1_STRING;
  TASN1_BOOLEAN = TOpenSSL_C_INT;
  TASN1_NULL = TOpenSSL_C_INT;
  {$endif}

type
  {Auto-generated forward references}
  Pasn1_type_st = ^TASN1_TYPE;
  PPasn1_type_st = ^Pasn1_type_st;
  PASN1_TYPE = ^TASN1_TYPE;
  PPASN1_TYPE = ^PASN1_TYPE;
  Pasn1_object_st = ^TASN1_OBJECT;
  PPasn1_object_st = ^Pasn1_object_st;
  PASN1_OBJECT = ^TASN1_OBJECT;
  PPASN1_OBJECT = ^PASN1_OBJECT;
  Pasn1_string_table_st = ^TASN1_STRING_TABLE;
  PPasn1_string_table_st = ^Pasn1_string_table_st;
  PASN1_STRING_TABLE = ^TASN1_STRING_TABLE;
  PPASN1_STRING_TABLE = ^PASN1_STRING_TABLE;
  PASN1_ITEM_st = ^TASN1_ITEM;
  PPASN1_ITEM_st = ^PASN1_ITEM_st;
  PASN1_ITEM = ^TASN1_ITEM;
  PPASN1_ITEM = ^PASN1_ITEM;
  Pasn1_pctx_st = ^TASN1_PCTX;
  PPasn1_pctx_st = ^Pasn1_pctx_st;
  PASN1_PCTX = ^TASN1_PCTX;
  PPASN1_PCTX = ^PASN1_PCTX;
  Pasn1_sctx_st = ^TASN1_SCTX;
  PPasn1_sctx_st = ^Pasn1_sctx_st;
  PASN1_SCTX = ^TASN1_SCTX;
  PPASN1_SCTX = ^PASN1_SCTX;
  {end of auto-generated forward references}

  Tasn1_type_st = record end;
  TASN1_TYPE = Tasn1_type_st;
  Tasn1_object_st = record end;
  TASN1_OBJECT = Tasn1_object_st;
  Tasn1_string_table_st = record end;
  TASN1_STRING_TABLE = Tasn1_string_table_st;
  TASN1_ITEM_st = record end;
  TASN1_ITEM = TASN1_ITEM_st;
  Tasn1_pctx_st = record end;
  TASN1_PCTX = Tasn1_pctx_st;
  Tasn1_sctx_st = record end;
  TASN1_SCTX = Tasn1_sctx_st;
  {$if declared(TBIGNUM)}
    {$undef  BIGNUM}
  {$endif}

type
  {Auto-generated forward references}
  Pbio_st = ^TBIO;
  PPbio_st = ^Pbio_st;
  PBIO = ^TBIO;
  PPBIO = ^PBIO;
  Pbignum_st = ^TBIGNUM;
  PPbignum_st = ^Pbignum_st;
  PBIGNUM = ^TBIGNUM;
  PPBIGNUM = ^PBIGNUM;
  Pbignum_ctx = ^TBN_CTX;
  PPbignum_ctx = ^Pbignum_ctx;
  PBN_CTX = ^TBN_CTX;
  PPBN_CTX = ^PBN_CTX;
  Pbn_blinding_st = ^TBN_BLINDING;
  PPbn_blinding_st = ^Pbn_blinding_st;
  PBN_BLINDING = ^TBN_BLINDING;
  PPBN_BLINDING = ^PBN_BLINDING;
  Pbn_mont_ctx_st = ^TBN_MONT_CTX;
  PPbn_mont_ctx_st = ^Pbn_mont_ctx_st;
  PBN_MONT_CTX = ^TBN_MONT_CTX;
  PPBN_MONT_CTX = ^PBN_MONT_CTX;
  Pbn_recp_ctx_st = ^TBN_RECP_CTX;
  PPbn_recp_ctx_st = ^Pbn_recp_ctx_st;
  PBN_RECP_CTX = ^TBN_RECP_CTX;
  PPBN_RECP_CTX = ^PBN_RECP_CTX;
  Pbn_gencb_st = ^TBN_GENCB;
  PPbn_gencb_st = ^Pbn_gencb_st;
  PBN_GENCB = ^TBN_GENCB;
  PPBN_GENCB = ^PBN_GENCB;
  Pbuf_mem_st = ^TBUF_MEM;
  PPbuf_mem_st = ^Pbuf_mem_st;
  PBUF_MEM = ^TBUF_MEM;
  PPBUF_MEM = ^PBUF_MEM;
  Pstack_st_BIGNUM = ^Tstack_st_BIGNUM;
  PPstack_st_BIGNUM = ^Pstack_st_BIGNUM;
  Pstack_st_BIGNUM_const = ^Tstack_st_BIGNUM_const;
  PPstack_st_BIGNUM_const = ^Pstack_st_BIGNUM_const;
  Perr_state_st = ^TERR_STATE;
  PPerr_state_st = ^Perr_state_st;
  PERR_STATE = ^TERR_STATE;
  PPERR_STATE = ^PERR_STATE;
  Pevp_cipher_st = ^TEVP_CIPHER;
  PPevp_cipher_st = ^Pevp_cipher_st;
  PEVP_CIPHER = ^TEVP_CIPHER;
  PPEVP_CIPHER = ^PEVP_CIPHER;
  Pevp_cipher_ctx_st = ^TEVP_CIPHER_CTX;
  PPevp_cipher_ctx_st = ^Pevp_cipher_ctx_st;
  PEVP_CIPHER_CTX = ^TEVP_CIPHER_CTX;
  PPEVP_CIPHER_CTX = ^PEVP_CIPHER_CTX;
  Pevp_md_st = ^TEVP_MD;
  PPevp_md_st = ^Pevp_md_st;
  PEVP_MD = ^TEVP_MD;
  PPEVP_MD = ^PEVP_MD;
  Pevp_md_ctx_st = ^TEVP_MD_CTX;
  PPevp_md_ctx_st = ^Pevp_md_ctx_st;
  PEVP_MD_CTX = ^TEVP_MD_CTX;
  PPEVP_MD_CTX = ^PEVP_MD_CTX;
  Pevp_mac_st = ^TEVP_MAC;
  PPevp_mac_st = ^Pevp_mac_st;
  PEVP_MAC = ^TEVP_MAC;
  PPEVP_MAC = ^PEVP_MAC;
  Pevp_mac_ctx_st = ^TEVP_MAC_CTX;
  PPevp_mac_ctx_st = ^Pevp_mac_ctx_st;
  PEVP_MAC_CTX = ^TEVP_MAC_CTX;
  PPEVP_MAC_CTX = ^PEVP_MAC_CTX;
  Pevp_pkey_st = ^TEVP_PKEY;
  PPevp_pkey_st = ^Pevp_pkey_st;
  PEVP_PKEY = ^TEVP_PKEY;
  PPEVP_PKEY = ^PEVP_PKEY;
  Pevp_skey_st = ^TEVP_SKEY;
  PPevp_skey_st = ^Pevp_skey_st;
  PEVP_SKEY = ^TEVP_SKEY;
  PPEVP_SKEY = ^PEVP_SKEY;
  Pevp_pkey_asn1_method_st = ^TEVP_PKEY_ASN1_METHOD;
  PPevp_pkey_asn1_method_st = ^Pevp_pkey_asn1_method_st;
  PEVP_PKEY_ASN1_METHOD = ^TEVP_PKEY_ASN1_METHOD;
  PPEVP_PKEY_ASN1_METHOD = ^PEVP_PKEY_ASN1_METHOD;
  Pevp_pkey_method_st = ^TEVP_PKEY_METHOD;
  PPevp_pkey_method_st = ^Pevp_pkey_method_st;
  PEVP_PKEY_METHOD = ^TEVP_PKEY_METHOD;
  PPEVP_PKEY_METHOD = ^PEVP_PKEY_METHOD;
  Pevp_pkey_ctx_st = ^TEVP_PKEY_CTX;
  PPevp_pkey_ctx_st = ^Pevp_pkey_ctx_st;
  PEVP_PKEY_CTX = ^TEVP_PKEY_CTX;
  PPEVP_PKEY_CTX = ^PEVP_PKEY_CTX;
  Pevp_keymgmt_st = ^TEVP_KEYMGMT;
  PPevp_keymgmt_st = ^Pevp_keymgmt_st;
  PEVP_KEYMGMT = ^TEVP_KEYMGMT;
  PPEVP_KEYMGMT = ^PEVP_KEYMGMT;
  Pevp_kdf_st = ^TEVP_KDF;
  PPevp_kdf_st = ^Pevp_kdf_st;
  PEVP_KDF = ^TEVP_KDF;
  PPEVP_KDF = ^PEVP_KDF;
  Pevp_kdf_ctx_st = ^TEVP_KDF_CTX;
  PPevp_kdf_ctx_st = ^Pevp_kdf_ctx_st;
  PEVP_KDF_CTX = ^TEVP_KDF_CTX;
  PPEVP_KDF_CTX = ^PEVP_KDF_CTX;
  Pevp_rand_st = ^TEVP_RAND;
  PPevp_rand_st = ^Pevp_rand_st;
  PEVP_RAND = ^TEVP_RAND;
  PPEVP_RAND = ^PEVP_RAND;
  Pevp_rand_ctx_st = ^TEVP_RAND_CTX;
  PPevp_rand_ctx_st = ^Pevp_rand_ctx_st;
  PEVP_RAND_CTX = ^TEVP_RAND_CTX;
  PPEVP_RAND_CTX = ^PEVP_RAND_CTX;
  Pevp_keyexch_st = ^TEVP_KEYEXCH;
  PPevp_keyexch_st = ^Pevp_keyexch_st;
  PEVP_KEYEXCH = ^TEVP_KEYEXCH;
  PPEVP_KEYEXCH = ^PEVP_KEYEXCH;
  Pevp_signature_st = ^TEVP_SIGNATURE;
  PPevp_signature_st = ^Pevp_signature_st;
  PEVP_SIGNATURE = ^TEVP_SIGNATURE;
  PPEVP_SIGNATURE = ^PEVP_SIGNATURE;
  Pevp_skeymgmt_st = ^TEVP_SKEYMGMT;
  PPevp_skeymgmt_st = ^Pevp_skeymgmt_st;
  PEVP_SKEYMGMT = ^TEVP_SKEYMGMT;
  PPEVP_SKEYMGMT = ^PEVP_SKEYMGMT;
  Pevp_asym_cipher_st = ^TEVP_ASYM_CIPHER;
  PPevp_asym_cipher_st = ^Pevp_asym_cipher_st;
  PEVP_ASYM_CIPHER = ^TEVP_ASYM_CIPHER;
  PPEVP_ASYM_CIPHER = ^PEVP_ASYM_CIPHER;
  Pevp_kem_st = ^TEVP_KEM;
  PPevp_kem_st = ^Pevp_kem_st;
  PEVP_KEM = ^TEVP_KEM;
  PPEVP_KEM = ^PEVP_KEM;
  Pevp_Encode_Ctx_st = ^TEVP_ENCODE_CTX;
  PPevp_Encode_Ctx_st = ^Pevp_Encode_Ctx_st;
  PEVP_ENCODE_CTX = ^TEVP_ENCODE_CTX;
  PPEVP_ENCODE_CTX = ^PEVP_ENCODE_CTX;
  Phmac_ctx_st = ^THMAC_CTX;
  PPhmac_ctx_st = ^Phmac_ctx_st;
  PHMAC_CTX = ^THMAC_CTX;
  PPHMAC_CTX = ^PHMAC_CTX;
  Pdh_st = ^TDH;
  PPdh_st = ^Pdh_st;
  PDH = ^TDH;
  PPDH = ^PDH;
  PDH_METHOD = ^TDH_METHOD;
  PPDH_METHOD = ^PDH_METHOD;
  {end of auto-generated forward references}

  Tbio_st = record end;
  TBIO = Tbio_st;
  Tbignum_st = record end;
  TBIGNUM = Tbignum_st;
  Tbignum_ctx = record end;
  TBN_CTX = Tbignum_ctx;
  Tbn_blinding_st = record end;
  TBN_BLINDING = Tbn_blinding_st;
  Tbn_mont_ctx_st = record end;
  TBN_MONT_CTX = Tbn_mont_ctx_st;
  Tbn_recp_ctx_st = record end;
  TBN_RECP_CTX = Tbn_recp_ctx_st;
  Tbn_gencb_st = record end;
  TBN_GENCB = Tbn_gencb_st;
  Tbuf_mem_st = record end;
  TBUF_MEM = Tbuf_mem_st;
  Tstack_st_BIGNUM = record 
  end;
  Tstack_st_BIGNUM_const = record 
  end;
  Terr_state_st = record end;
  TERR_STATE = Terr_state_st;
  Tevp_cipher_st = record end;
  TEVP_CIPHER = Tevp_cipher_st;
  Tevp_cipher_ctx_st = record end;
  TEVP_CIPHER_CTX = Tevp_cipher_ctx_st;
  Tevp_md_st = record end;
  TEVP_MD = Tevp_md_st;
  Tevp_md_ctx_st = record end;
  TEVP_MD_CTX = Tevp_md_ctx_st;
  Tevp_mac_st = record end;
  TEVP_MAC = Tevp_mac_st;
  Tevp_mac_ctx_st = record end;
  TEVP_MAC_CTX = Tevp_mac_ctx_st;
  Tevp_pkey_st = record end;
  TEVP_PKEY = Tevp_pkey_st;
  Tevp_skey_st = record end;
  TEVP_SKEY = Tevp_skey_st;
  Tevp_pkey_asn1_method_st = record end;
  TEVP_PKEY_ASN1_METHOD = Tevp_pkey_asn1_method_st;
  Tevp_pkey_method_st = record end;
  TEVP_PKEY_METHOD = Tevp_pkey_method_st;
  Tevp_pkey_ctx_st = record end;
  TEVP_PKEY_CTX = Tevp_pkey_ctx_st;
  Tevp_keymgmt_st = record end;
  TEVP_KEYMGMT = Tevp_keymgmt_st;
  Tevp_kdf_st = record end;
  TEVP_KDF = Tevp_kdf_st;
  Tevp_kdf_ctx_st = record end;
  TEVP_KDF_CTX = Tevp_kdf_ctx_st;
  Tevp_rand_st = record end;
  TEVP_RAND = Tevp_rand_st;
  Tevp_rand_ctx_st = record end;
  TEVP_RAND_CTX = Tevp_rand_ctx_st;
  Tevp_keyexch_st = record end;
  TEVP_KEYEXCH = Tevp_keyexch_st;
  Tevp_signature_st = record end;
  TEVP_SIGNATURE = Tevp_signature_st;
  Tevp_skeymgmt_st = record end;
  TEVP_SKEYMGMT = Tevp_skeymgmt_st;
  Tevp_asym_cipher_st = record end;
  TEVP_ASYM_CIPHER = Tevp_asym_cipher_st;
  Tevp_kem_st = record end;
  TEVP_KEM = Tevp_kem_st;
  Tevp_Encode_Ctx_st = record end;
  TEVP_ENCODE_CTX = Tevp_Encode_Ctx_st;
  Thmac_ctx_st = record end;
  THMAC_CTX = Thmac_ctx_st;
  Tdh_st = record end;
  TDH = Tdh_st;
  TDH_METHOD = record end;

  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  Pdsa_st = ^TDSA;
  PPdsa_st = ^Pdsa_st;
  PDSA = ^TDSA;
  PPDSA = ^PDSA;
  PDSA_METHOD = ^TDSA_METHOD;
  PPDSA_METHOD = ^PDSA_METHOD;
  {end of auto-generated forward references}

  Tdsa_st = record end;
  TDSA = Tdsa_st;
  TDSA_METHOD = record end;

  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  Prsa_st = ^TRSA;
  PPrsa_st = ^Prsa_st;
  PRSA = ^TRSA;
  PPRSA = ^PRSA;
  Prsa_meth_st = ^TRSA_METHOD;
  PPrsa_meth_st = ^Prsa_meth_st;
  PRSA_METHOD = ^TRSA_METHOD;
  PPRSA_METHOD = ^PRSA_METHOD;
  {end of auto-generated forward references}

  Trsa_st = record end;
  TRSA = Trsa_st;
  Trsa_meth_st = record end;
  TRSA_METHOD = Trsa_meth_st;
  {$endif}

type
  {Auto-generated forward references}
  Prsa_pss_params_st = ^TRSA_PSS_PARAMS;
  PPrsa_pss_params_st = ^Prsa_pss_params_st;
  PRSA_PSS_PARAMS = ^TRSA_PSS_PARAMS;
  PPRSA_PSS_PARAMS = ^PRSA_PSS_PARAMS;
  Prsa_oaep_params_st = ^TRSA_OAEP_PARAMS;
  PPrsa_oaep_params_st = ^Prsa_oaep_params_st;
  PRSA_OAEP_PARAMS = ^TRSA_OAEP_PARAMS;
  PPRSA_OAEP_PARAMS = ^PRSA_OAEP_PARAMS;
  {end of auto-generated forward references}

  Trsa_pss_params_st = record end;
  TRSA_PSS_PARAMS = Trsa_pss_params_st;
  Trsa_oaep_params_st = record end;
  TRSA_OAEP_PARAMS = Trsa_oaep_params_st;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  Pec_key_st = ^TEC_KEY;
  PPec_key_st = ^Pec_key_st;
  PEC_KEY = ^TEC_KEY;
  PPEC_KEY = ^PEC_KEY;
  Pec_key_method_st = ^TEC_KEY_METHOD;
  PPec_key_method_st = ^Pec_key_method_st;
  PEC_KEY_METHOD = ^TEC_KEY_METHOD;
  PPEC_KEY_METHOD = ^PEC_KEY_METHOD;
  {end of auto-generated forward references}

  Tec_key_st = record end;
  TEC_KEY = Tec_key_st;
  Tec_key_method_st = record end;
  TEC_KEY_METHOD = Tec_key_method_st;
  {$endif}

type
  {Auto-generated forward references}
  Prand_meth_st = ^TRAND_METHOD;
  PPrand_meth_st = ^Prand_meth_st;
  PRAND_METHOD = ^TRAND_METHOD;
  PPRAND_METHOD = ^PRAND_METHOD;
  Prand_drbg_st = ^TRAND_DRBG;
  PPrand_drbg_st = ^Prand_drbg_st;
  PRAND_DRBG = ^TRAND_DRBG;
  PPRAND_DRBG = ^PRAND_DRBG;
  Pssl_dane_st = ^TSSL_DANE;
  PPssl_dane_st = ^Pssl_dane_st;
  PSSL_DANE = ^TSSL_DANE;
  PPSSL_DANE = ^PSSL_DANE;
  Px509_st = ^TX509;
  PPx509_st = ^Px509_st;
  PX509 = ^TX509;
  PPX509 = ^PX509;
  PX509_algor_st = ^TX509_ALGOR;
  PPX509_algor_st = ^PX509_algor_st;
  PX509_ALGOR = ^TX509_ALGOR;
  PPX509_ALGOR = ^PX509_ALGOR;
  PX509_crl_st = ^TX509_CRL;
  PPX509_crl_st = ^PX509_crl_st;
  PX509_CRL = ^TX509_CRL;
  PPX509_CRL = ^PX509_CRL;
  Px509_crl_method_st = ^TX509_CRL_METHOD;
  PPx509_crl_method_st = ^Px509_crl_method_st;
  PX509_CRL_METHOD = ^TX509_CRL_METHOD;
  PPX509_CRL_METHOD = ^PX509_CRL_METHOD;
  Px509_revoked_st = ^TX509_REVOKED;
  PPx509_revoked_st = ^Px509_revoked_st;
  PX509_REVOKED = ^TX509_REVOKED;
  PPX509_REVOKED = ^PX509_REVOKED;
  PX509_name_st = ^TX509_NAME;
  PPX509_name_st = ^PX509_name_st;
  PX509_NAME = ^TX509_NAME;
  PPX509_NAME = ^PX509_NAME;
  PX509_pubkey_st = ^TX509_PUBKEY;
  PPX509_pubkey_st = ^PX509_pubkey_st;
  PX509_PUBKEY = ^TX509_PUBKEY;
  PPX509_PUBKEY = ^PX509_PUBKEY;
  Px509_store_st = ^TX509_STORE;
  PPx509_store_st = ^Px509_store_st;
  PX509_STORE = ^TX509_STORE;
  PPX509_STORE = ^PX509_STORE;
  Px509_store_ctx_st = ^TX509_STORE_CTX;
  PPx509_store_ctx_st = ^Px509_store_ctx_st;
  PX509_STORE_CTX = ^TX509_STORE_CTX;
  PPX509_STORE_CTX = ^PX509_STORE_CTX;
  Px509_object_st = ^TX509_OBJECT;
  PPx509_object_st = ^Px509_object_st;
  PX509_OBJECT = ^TX509_OBJECT;
  PPX509_OBJECT = ^PX509_OBJECT;
  Px509_lookup_st = ^TX509_LOOKUP;
  PPx509_lookup_st = ^Px509_lookup_st;
  PX509_LOOKUP = ^TX509_LOOKUP;
  PPX509_LOOKUP = ^PX509_LOOKUP;
  Px509_lookup_method_st = ^TX509_LOOKUP_METHOD;
  PPx509_lookup_method_st = ^Px509_lookup_method_st;
  PX509_LOOKUP_METHOD = ^TX509_LOOKUP_METHOD;
  PPX509_LOOKUP_METHOD = ^PX509_LOOKUP_METHOD;
  PX509_VERIFY_PARAM_st = ^TX509_VERIFY_PARAM;
  PPX509_VERIFY_PARAM_st = ^PX509_VERIFY_PARAM_st;
  PX509_VERIFY_PARAM = ^TX509_VERIFY_PARAM;
  PPX509_VERIFY_PARAM = ^PX509_VERIFY_PARAM;
  Px509_sig_info_st = ^TX509_SIG_INFO;
  PPx509_sig_info_st = ^Px509_sig_info_st;
  PX509_SIG_INFO = ^TX509_SIG_INFO;
  PPX509_SIG_INFO = ^PX509_SIG_INFO;
  Ppkcs8_priv_key_info_st = ^TPKCS8_PRIV_KEY_INFO;
  PPpkcs8_priv_key_info_st = ^Ppkcs8_priv_key_info_st;
  PPKCS8_PRIV_KEY_INFO = ^TPKCS8_PRIV_KEY_INFO;
  PPPKCS8_PRIV_KEY_INFO = ^PPKCS8_PRIV_KEY_INFO;
  Pv3_ext_ctx = ^TX509V3_CTX;
  PPv3_ext_ctx = ^Pv3_ext_ctx;
  PX509V3_CTX = ^TX509V3_CTX;
  PPX509V3_CTX = ^PX509V3_CTX;
  Pconf_st = ^TCONF;
  PPconf_st = ^Pconf_st;
  PCONF = ^TCONF;
  PPCONF = ^PCONF;
  Possl_init_settings_st = ^TOPENSSL_INIT_SETTINGS;
  PPossl_init_settings_st = ^Possl_init_settings_st;
  POPENSSL_INIT_SETTINGS = ^TOPENSSL_INIT_SETTINGS;
  PPOPENSSL_INIT_SETTINGS = ^POPENSSL_INIT_SETTINGS;
  Pui_st = ^TUI;
  PPui_st = ^Pui_st;
  PUI = ^TUI;
  PPUI = ^PUI;
  Pui_method_st = ^TUI_METHOD;
  PPui_method_st = ^Pui_method_st;
  PUI_METHOD = ^TUI_METHOD;
  PPUI_METHOD = ^PUI_METHOD;
  Pengine_st = ^TENGINE;
  PPengine_st = ^Pengine_st;
  PENGINE = ^TENGINE;
  PPENGINE = ^PENGINE;
  Pssl_st = ^TSSL;
  PPssl_st = ^Pssl_st;
  PSSL = ^TSSL;
  PPSSL = ^PSSL;
  Pssl_ctx_st = ^TSSL_CTX;
  PPssl_ctx_st = ^Pssl_ctx_st;
  PSSL_CTX = ^TSSL_CTX;
  PPSSL_CTX = ^PSSL_CTX;
  Pcomp_ctx_st = ^TCOMP_CTX;
  PPcomp_ctx_st = ^Pcomp_ctx_st;
  PCOMP_CTX = ^TCOMP_CTX;
  PPCOMP_CTX = ^PCOMP_CTX;
  Pcomp_method_st = ^TCOMP_METHOD;
  PPcomp_method_st = ^Pcomp_method_st;
  PCOMP_METHOD = ^TCOMP_METHOD;
  PPCOMP_METHOD = ^PCOMP_METHOD;
  PX509_POLICY_NODE_st = ^TX509_POLICY_NODE;
  PPX509_POLICY_NODE_st = ^PX509_POLICY_NODE_st;
  PX509_POLICY_NODE = ^TX509_POLICY_NODE;
  PPX509_POLICY_NODE = ^PX509_POLICY_NODE;
  PX509_POLICY_LEVEL_st = ^TX509_POLICY_LEVEL;
  PPX509_POLICY_LEVEL_st = ^PX509_POLICY_LEVEL_st;
  PX509_POLICY_LEVEL = ^TX509_POLICY_LEVEL;
  PPX509_POLICY_LEVEL = ^PX509_POLICY_LEVEL;
  PX509_POLICY_TREE_st = ^TX509_POLICY_TREE;
  PPX509_POLICY_TREE_st = ^PX509_POLICY_TREE_st;
  PX509_POLICY_TREE = ^TX509_POLICY_TREE;
  PPX509_POLICY_TREE = ^PX509_POLICY_TREE;
  PX509_POLICY_CACHE_st = ^TX509_POLICY_CACHE;
  PPX509_POLICY_CACHE_st = ^PX509_POLICY_CACHE_st;
  PX509_POLICY_CACHE = ^TX509_POLICY_CACHE;
  PPX509_POLICY_CACHE = ^PX509_POLICY_CACHE;
  PAUTHORITY_KEYID_st = ^TAUTHORITY_KEYID;
  PPAUTHORITY_KEYID_st = ^PAUTHORITY_KEYID_st;
  PAUTHORITY_KEYID = ^TAUTHORITY_KEYID;
  PPAUTHORITY_KEYID = ^PAUTHORITY_KEYID;
  PDIST_POINT_st = ^TDIST_POINT;
  PPDIST_POINT_st = ^PDIST_POINT_st;
  PDIST_POINT = ^TDIST_POINT;
  PPDIST_POINT = ^PDIST_POINT;
  PISSUING_DIST_POINT_st = ^TISSUING_DIST_POINT;
  PPISSUING_DIST_POINT_st = ^PISSUING_DIST_POINT_st;
  PISSUING_DIST_POINT = ^TISSUING_DIST_POINT;
  PPISSUING_DIST_POINT = ^PISSUING_DIST_POINT;
  PNAME_CONSTRAINTS_st = ^TNAME_CONSTRAINTS;
  PPNAME_CONSTRAINTS_st = ^PNAME_CONSTRAINTS_st;
  PNAME_CONSTRAINTS = ^TNAME_CONSTRAINTS;
  PPNAME_CONSTRAINTS = ^PNAME_CONSTRAINTS;
  Pcrypto_ex_data_st = ^TCRYPTO_EX_DATA;
  PPcrypto_ex_data_st = ^Pcrypto_ex_data_st;
  PCRYPTO_EX_DATA = ^TCRYPTO_EX_DATA;
  PPCRYPTO_EX_DATA = ^PCRYPTO_EX_DATA;
  Possl_http_req_ctx_st = ^TOSSL_HTTP_REQ_CTX;
  PPossl_http_req_ctx_st = ^Possl_http_req_ctx_st;
  POSSL_HTTP_REQ_CTX = ^TOSSL_HTTP_REQ_CTX;
  PPOSSL_HTTP_REQ_CTX = ^POSSL_HTTP_REQ_CTX;
  Pocsp_response_st = ^TOCSP_RESPONSE;
  PPocsp_response_st = ^Pocsp_response_st;
  POCSP_RESPONSE = ^TOCSP_RESPONSE;
  PPOCSP_RESPONSE = ^POCSP_RESPONSE;
  Pocsp_responder_id_st = ^TOCSP_RESPID;
  PPocsp_responder_id_st = ^Pocsp_responder_id_st;
  POCSP_RESPID = ^TOCSP_RESPID;
  PPOCSP_RESPID = ^POCSP_RESPID;
  Psct_st = ^TSCT;
  PPsct_st = ^Psct_st;
  PSCT = ^TSCT;
  PPSCT = ^PSCT;
  Psct_ctx_st = ^TSCT_CTX;
  PPsct_ctx_st = ^Psct_ctx_st;
  PSCT_CTX = ^TSCT_CTX;
  PPSCT_CTX = ^PSCT_CTX;
  Pctlog_st = ^TCTLOG;
  PPctlog_st = ^Pctlog_st;
  PCTLOG = ^TCTLOG;
  PPCTLOG = ^PCTLOG;
  Pctlog_store_st = ^TCTLOG_STORE;
  PPctlog_store_st = ^Pctlog_store_st;
  PCTLOG_STORE = ^TCTLOG_STORE;
  PPCTLOG_STORE = ^PCTLOG_STORE;
  Pct_policy_eval_ctx_st = ^TCT_POLICY_EVAL_CTX;
  PPct_policy_eval_ctx_st = ^Pct_policy_eval_ctx_st;
  PCT_POLICY_EVAL_CTX = ^TCT_POLICY_EVAL_CTX;
  PPCT_POLICY_EVAL_CTX = ^PCT_POLICY_EVAL_CTX;
  Possl_store_info_st = ^TOSSL_STORE_INFO;
  PPossl_store_info_st = ^Possl_store_info_st;
  POSSL_STORE_INFO = ^TOSSL_STORE_INFO;
  PPOSSL_STORE_INFO = ^POSSL_STORE_INFO;
  Possl_store_search_st = ^TOSSL_STORE_SEARCH;
  PPossl_store_search_st = ^Possl_store_search_st;
  POSSL_STORE_SEARCH = ^TOSSL_STORE_SEARCH;
  PPOSSL_STORE_SEARCH = ^POSSL_STORE_SEARCH;
  Possl_lib_ctx_st = ^TOSSL_LIB_CTX;
  PPossl_lib_ctx_st = ^Possl_lib_ctx_st;
  POSSL_LIB_CTX = ^TOSSL_LIB_CTX;
  PPOSSL_LIB_CTX = ^POSSL_LIB_CTX;
  Possl_dispatch_st = ^TOSSL_DISPATCH;
  PPossl_dispatch_st = ^Possl_dispatch_st;
  POSSL_DISPATCH = ^TOSSL_DISPATCH;
  PPOSSL_DISPATCH = ^POSSL_DISPATCH;
  Possl_item_st = ^TOSSL_ITEM;
  PPossl_item_st = ^Possl_item_st;
  POSSL_ITEM = ^TOSSL_ITEM;
  PPOSSL_ITEM = ^POSSL_ITEM;
  Possl_algorithm_st = ^TOSSL_ALGORITHM;
  PPossl_algorithm_st = ^Possl_algorithm_st;
  POSSL_ALGORITHM = ^TOSSL_ALGORITHM;
  PPOSSL_ALGORITHM = ^POSSL_ALGORITHM;
  Possl_param_st = ^TOSSL_PARAM;
  PPossl_param_st = ^Possl_param_st;
  POSSL_PARAM = ^TOSSL_PARAM;
  PPOSSL_PARAM = ^POSSL_PARAM;
  Possl_param_bld_st = ^TOSSL_PARAM_BLD;
  PPossl_param_bld_st = ^Possl_param_bld_st;
  POSSL_PARAM_BLD = ^TOSSL_PARAM_BLD;
  PPOSSL_PARAM_BLD = ^POSSL_PARAM_BLD;
  Ppem_password_cb = ^Tpem_password_cb;
  PPpem_password_cb = ^Ppem_password_cb;
  Possl_encoder_st = ^TOSSL_ENCODER;
  PPossl_encoder_st = ^Possl_encoder_st;
  POSSL_ENCODER = ^TOSSL_ENCODER;
  PPOSSL_ENCODER = ^POSSL_ENCODER;
  Possl_encoder_ctx_st = ^TOSSL_ENCODER_CTX;
  PPossl_encoder_ctx_st = ^Possl_encoder_ctx_st;
  POSSL_ENCODER_CTX = ^TOSSL_ENCODER_CTX;
  PPOSSL_ENCODER_CTX = ^POSSL_ENCODER_CTX;
  Possl_decoder_st = ^TOSSL_DECODER;
  PPossl_decoder_st = ^Possl_decoder_st;
  POSSL_DECODER = ^TOSSL_DECODER;
  PPOSSL_DECODER = ^POSSL_DECODER;
  Possl_decoder_ctx_st = ^TOSSL_DECODER_CTX;
  PPossl_decoder_ctx_st = ^Possl_decoder_ctx_st;
  POSSL_DECODER_CTX = ^TOSSL_DECODER_CTX;
  PPOSSL_DECODER_CTX = ^POSSL_DECODER_CTX;
  Possl_self_test_st = ^TOSSL_SELF_TEST;
  PPossl_self_test_st = ^Possl_self_test_st;
  POSSL_SELF_TEST = ^TOSSL_SELF_TEST;
  PPOSSL_SELF_TEST = ^POSSL_SELF_TEST;
  {end of auto-generated forward references}

  Trand_meth_st = record end;
  TRAND_METHOD = Trand_meth_st;
  Trand_drbg_st = record end;
  TRAND_DRBG = Trand_drbg_st;
  Tssl_dane_st = record end;
  TSSL_DANE = Tssl_dane_st;
  Tx509_st = record end;
  TX509 = Tx509_st;
  TX509_algor_st = record end;
  TX509_ALGOR = TX509_algor_st;
  TX509_crl_st = record end;
  TX509_CRL = TX509_crl_st;
  Tx509_crl_method_st = record end;
  TX509_CRL_METHOD = Tx509_crl_method_st;
  Tx509_revoked_st = record end;
  TX509_REVOKED = Tx509_revoked_st;
  TX509_name_st = record end;
  TX509_NAME = TX509_name_st;
  TX509_pubkey_st = record end;
  TX509_PUBKEY = TX509_pubkey_st;
  Tx509_store_st = record end;
  TX509_STORE = Tx509_store_st;
  Tx509_store_ctx_st = record end;
  TX509_STORE_CTX = Tx509_store_ctx_st;
  Tx509_object_st = record end;
  TX509_OBJECT = Tx509_object_st;
  Tx509_lookup_st = record end;
  TX509_LOOKUP = Tx509_lookup_st;
  Tx509_lookup_method_st = record end;
  TX509_LOOKUP_METHOD = Tx509_lookup_method_st;
  TX509_VERIFY_PARAM_st = record end;
  TX509_VERIFY_PARAM = TX509_VERIFY_PARAM_st;
  Tx509_sig_info_st = record end;
  TX509_SIG_INFO = Tx509_sig_info_st;
  Tpkcs8_priv_key_info_st = record end;
  TPKCS8_PRIV_KEY_INFO = Tpkcs8_priv_key_info_st;
  Tv3_ext_ctx = record end;
  TX509V3_CTX = Tv3_ext_ctx;
  Tconf_st = record end;
  TCONF = Tconf_st;
  Tossl_init_settings_st = record end;
  TOPENSSL_INIT_SETTINGS = Tossl_init_settings_st;
  Tui_st = record end;
  TUI = Tui_st;
  Tui_method_st = record end;
  TUI_METHOD = Tui_method_st;
  Tengine_st = record end;
  TENGINE = Tengine_st;
  Tssl_st = record end;
  TSSL = Tssl_st;
  Tssl_ctx_st = record end;
  TSSL_CTX = Tssl_ctx_st;
  Tcomp_ctx_st = record end;
  TCOMP_CTX = Tcomp_ctx_st;
  Tcomp_method_st = record end;
  TCOMP_METHOD = Tcomp_method_st;
  TX509_POLICY_NODE_st = record end;
  TX509_POLICY_NODE = TX509_POLICY_NODE_st;
  TX509_POLICY_LEVEL_st = record end;
  TX509_POLICY_LEVEL = TX509_POLICY_LEVEL_st;
  TX509_POLICY_TREE_st = record end;
  TX509_POLICY_TREE = TX509_POLICY_TREE_st;
  TX509_POLICY_CACHE_st = record end;
  TX509_POLICY_CACHE = TX509_POLICY_CACHE_st;
  TAUTHORITY_KEYID_st = record end;
  TAUTHORITY_KEYID = TAUTHORITY_KEYID_st;
  TDIST_POINT_st = record end;
  TDIST_POINT = TDIST_POINT_st;
  TISSUING_DIST_POINT_st = record end;
  TISSUING_DIST_POINT = TISSUING_DIST_POINT_st;
  TNAME_CONSTRAINTS_st = record end;
  TNAME_CONSTRAINTS = TNAME_CONSTRAINTS_st;
  Tcrypto_ex_data_st = record end;
  TCRYPTO_EX_DATA = Tcrypto_ex_data_st;
  Tossl_http_req_ctx_st = record end;
  TOSSL_HTTP_REQ_CTX = Tossl_http_req_ctx_st;
  Tocsp_response_st = record end;
  TOCSP_RESPONSE = Tocsp_response_st;
  Tocsp_responder_id_st = record end;
  TOCSP_RESPID = Tocsp_responder_id_st;
  Tsct_st = record end;
  TSCT = Tsct_st;
  Tsct_ctx_st = record end;
  TSCT_CTX = Tsct_ctx_st;
  Tctlog_st = record end;
  TCTLOG = Tctlog_st;
  Tctlog_store_st = record end;
  TCTLOG_STORE = Tctlog_store_st;
  Tct_policy_eval_ctx_st = record end;
  TCT_POLICY_EVAL_CTX = Tct_policy_eval_ctx_st;
  Tossl_store_info_st = record end;
  TOSSL_STORE_INFO = Tossl_store_info_st;
  Tossl_store_search_st = record end;
  TOSSL_STORE_SEARCH = Tossl_store_search_st;
  Tossl_lib_ctx_st = record end;
  TOSSL_LIB_CTX = Tossl_lib_ctx_st;
  Tossl_dispatch_st = record end;
  TOSSL_DISPATCH = Tossl_dispatch_st;
  Tossl_item_st = record end;
  TOSSL_ITEM = Tossl_item_st;
  Tossl_algorithm_st = record end;
  TOSSL_ALGORITHM = Tossl_algorithm_st;
  Tossl_param_st = record end;
  TOSSL_PARAM = Tossl_param_st;
  Tossl_param_bld_st = record end;
  TOSSL_PARAM_BLD = Tossl_param_bld_st;
  Tpem_password_cb = function(buf: PAnsiChar; size: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: pointer): TOpenSSL_C_INT; cdecl;
  Tossl_encoder_st = record end;
  TOSSL_ENCODER = Tossl_encoder_st;
  Tossl_encoder_ctx_st = record end;
  TOSSL_ENCODER_CTX = Tossl_encoder_ctx_st;
  Tossl_decoder_st = record end;
  TOSSL_DECODER = Tossl_decoder_st;
  Tossl_decoder_ctx_st = record end;
  TOSSL_DECODER_CTX = Tossl_decoder_ctx_st;
  Tossl_self_test_st = record end;
  TOSSL_SELF_TEST = Tossl_self_test_st;
{$endif}
{ OPENSSL_TYPES_H }

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
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
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



