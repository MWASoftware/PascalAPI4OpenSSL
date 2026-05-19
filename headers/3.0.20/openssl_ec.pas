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

unit openssl_ec;

{
  Generated from OpenSSL 3.0.20 Header File ec.h - Tue 19 May 14:15:56 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_ec.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_evp,openssl_types,openssl_asn1,openssl_symhacks,
     openssl_bn,openssl_ecerr,openssl_params;


{* Copyright 2002-2026 The OpenSSL Project Authors. All Rights Reserved.
* Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_EC_H}
  {$define OPENSSL_EC_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_EC_H}
  {$endif}
  {$include openssl_opensslconf.inc}

const
  { Values for EVP_PKEY_CTX_set_ec_param_enc() }
  OPENSSL_EC_EXPLICIT_CURVE = $000;
  OPENSSL_EC_NAMED_CURVE = $001;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_ec_paramgen_curve_nid';
  function EVP_PKEY_CTX_set_ec_param_enc(ctx: PEVP_PKEY_CTX; param_enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_ec_param_enc';
  function EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX; cofactor_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_cofactor_mode';
  function EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_cofactor_mode';
  function EVP_PKEY_CTX_set_ecdh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_kdf_type';
  function EVP_PKEY_CTX_get_ecdh_kdf_type(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_kdf_type';
  function EVP_PKEY_CTX_set_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_kdf_md';
  function EVP_PKEY_CTX_get_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_kdf_md';
  function EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_kdf_outlen';
  function EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_kdf_outlen';
  function EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set0_ecdh_kdf_ukm';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM EVP_PKEY_CTX_set_ec_paramgen_curve_nid}
  {$EXTERNALSYM EVP_PKEY_CTX_set_ec_param_enc}
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_cofactor_mode}
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_cofactor_mode}
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_kdf_type}
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_kdf_type}
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_kdf_md}
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_kdf_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_kdf_outlen}
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_kdf_outlen}
  {$EXTERNALSYM EVP_PKEY_CTX_set0_ecdh_kdf_ukm}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_ec_param_enc(ctx: PEVP_PKEY_CTX; param_enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX; cofactor_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_ecdh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_ecdh_kdf_type(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid: function(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
  EVP_PKEY_CTX_set_ec_param_enc: function(ctx: PEVP_PKEY_CTX; param_enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_ec_param_enc;
  EVP_PKEY_CTX_set_ecdh_cofactor_mode: function(ctx: PEVP_PKEY_CTX; cofactor_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_ecdh_cofactor_mode;
  EVP_PKEY_CTX_get_ecdh_cofactor_mode: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_ecdh_cofactor_mode;
  EVP_PKEY_CTX_set_ecdh_kdf_type: function(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_ecdh_kdf_type;
  EVP_PKEY_CTX_get_ecdh_kdf_type: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_ecdh_kdf_type;
  EVP_PKEY_CTX_set_ecdh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_ecdh_kdf_md;
  EVP_PKEY_CTX_get_ecdh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_ecdh_kdf_md;
  EVP_PKEY_CTX_set_ecdh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_ecdh_kdf_outlen;
  EVP_PKEY_CTX_get_ecdh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_ecdh_kdf_outlen;
  EVP_PKEY_CTX_set0_ecdh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set0_ecdh_kdf_ukm;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_ecdh_kdf_ukm'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_ecdh_kdf_ukm}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_get0_ecdh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get0_ecdh_kdf_ukm;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}

const
  EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = EVP_PKEY_ALG_CTRL+1;
  EVP_PKEY_CTRL_EC_PARAM_ENC = EVP_PKEY_ALG_CTRL+2;
  EVP_PKEY_CTRL_EC_ECDH_COFACTOR = EVP_PKEY_ALG_CTRL+3;
  EVP_PKEY_CTRL_EC_KDF_TYPE = EVP_PKEY_ALG_CTRL+4;
  EVP_PKEY_CTRL_EC_KDF_MD = EVP_PKEY_ALG_CTRL+5;
  EVP_PKEY_CTRL_GET_EC_KDF_MD = EVP_PKEY_ALG_CTRL+6;
  EVP_PKEY_CTRL_EC_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+7;
  EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+8;
  EVP_PKEY_CTRL_EC_KDF_UKM = EVP_PKEY_ALG_CTRL+9;
  EVP_PKEY_CTRL_GET_EC_KDF_UKM = EVP_PKEY_ALG_CTRL+10;
  { KDF types }
  EVP_PKEY_ECDH_KDF_NONE = 1;
  EVP_PKEY_ECDH_KDF_X9_63 = 2;
  
  {* The old name for EVP_PKEY_ECDH_KDF_X9_63
  *  The ECDH KDF specification has been mistakenly attributed to ANSI X9.62,
  *  it is actually specified in ANSI X9.63.
  *  This identifier is retained for backwards compatibility
  }
  EVP_PKEY_ECDH_KDF_X9_62 = EVP_PKEY_ECDH_KDF_X9_63;

type
  {Auto-generated forward references}
  Ppoint_conversion_form_t = ^Tpoint_conversion_form_t;
  PPpoint_conversion_form_t = ^Ppoint_conversion_form_t;
  {end of auto-generated forward references}

  {* Enum for the point conversion form as defined in X9.62 (ECDSA)
  *  for the encoding of a elliptic curve point (x,y) }
  {* the point is encoded as z||x, where the octet z specifies
  *  which solution of the quadratic equation y is  }
  Tpoint_conversion_form_t = (
    POINT_CONVERSION_COMPRESSED = 2, 
    POINT_CONVERSION_UNCOMPRESSED = 4, 
    POINT_CONVERSION_HYBRID = 6
  );


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_EC_curve_nid2name(nid: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_EC_curve_nid2name';
  {$else}
  {$EXTERNALSYM OSSL_EC_curve_nid2name}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_EC_curve_nid2name(nid: TOpenSSL_C_INT): PAnsiChar; cdecl;

var
  OSSL_EC_curve_nid2name: function(nid: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OSSL_EC_curve_nid2name;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_EC}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
    {$endif}
    {$ifndef  OPENSSL_ECC_MAX_FIELD_BITS}

const
  OPENSSL_ECC_MAX_FIELD_BITS = 661;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  Pec_method_st = ^TEC_METHOD;
  PPec_method_st = ^Pec_method_st;
  PEC_METHOD = ^TEC_METHOD;
  PPEC_METHOD = ^PEC_METHOD;
  {end of auto-generated forward references}

  Tec_method_st = record end;
  TEC_METHOD = Tec_method_st;
    {$endif}

type
  {Auto-generated forward references}
  Pec_group_st = ^TEC_GROUP;
  PPec_group_st = ^Pec_group_st;
  PEC_GROUP = ^TEC_GROUP;
  PPEC_GROUP = ^PEC_GROUP;
  Pec_point_st = ^TEC_POINT;
  PPec_point_st = ^Pec_point_st;
  PEC_POINT = ^TEC_POINT;
  PPEC_POINT = ^PEC_POINT;
  Pecpk_parameters_st = ^TECPKPARAMETERS;
  PPecpk_parameters_st = ^Pecpk_parameters_st;
  PECPKPARAMETERS = ^TECPKPARAMETERS;
  PPECPKPARAMETERS = ^PECPKPARAMETERS;
  Pec_parameters_st = ^TECPARAMETERS;
  PPec_parameters_st = ^Pec_parameters_st;
  PECPARAMETERS = ^TECPARAMETERS;
  PPECPARAMETERS = ^PECPARAMETERS;
  {end of auto-generated forward references}

  Tec_group_st = record end;
  TEC_GROUP = Tec_group_st;
  Tec_point_st = record end;
  TEC_POINT = Tec_point_st;
  Tecpk_parameters_st = record end;
  TECPKPARAMETERS = Tecpk_parameters_st;
  Tec_parameters_st = record end;
  TECPARAMETERS = Tec_parameters_st;
    {******************************************************************}
    {               EC_METHODs for curves over GF(p)                   }
    {******************************************************************}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {* Returns the basic GFp ec methods which provides the basis for the
      *  optimized methods.
      *  return  EC_METHOD object
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GFp_simple_method: PEC_METHOD; cdecl; external CLibCrypto name 'EC_GFp_simple_method'; deprecated 'Since OpenSSL 3.0';
  {* Returns GFp methods using montgomery multiplication.
  *  return  EC_METHOD object
  }
  function EC_GFp_mont_method: PEC_METHOD; cdecl; external CLibCrypto name 'EC_GFp_mont_method'; deprecated 'Since OpenSSL 3.0';
  {* Returns GFp methods using optimized methods for NIST recommended curves
  *  return  EC_METHOD object
  }
  function EC_GFp_nist_method: PEC_METHOD; cdecl; external CLibCrypto name 'EC_GFp_nist_method'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_GFp_simple_method}
  {$EXTERNALSYM EC_GFp_mont_method}
  {$EXTERNALSYM EC_GFp_nist_method}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GFp_simple_method: PEC_METHOD; cdecl;
  function Load_EC_GFp_mont_method: PEC_METHOD; cdecl;
  function Load_EC_GFp_nist_method: PEC_METHOD; cdecl;

var
  EC_GFp_simple_method: function: PEC_METHOD; cdecl = Load_EC_GFp_simple_method;
  {* Returns GFp methods using montgomery multiplication.
  *  return  EC_METHOD object
  }
  EC_GFp_mont_method: function: PEC_METHOD; cdecl = Load_EC_GFp_mont_method;
  {* Returns GFp methods using optimized methods for NIST recommended curves
  *  return  EC_METHOD object
  }
  EC_GFp_nist_method: function: PEC_METHOD; cdecl = Load_EC_GFp_nist_method;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$ifndef  OPENSSL_NO_EC_NISTP_64_GCC_128}


        {* Returns 64-bit optimized methods for nistp224
        *  return  EC_METHOD object
        }
        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GFp_nistp224_method: PEC_METHOD; cdecl; external CLibCrypto name 'EC_GFp_nistp224_method'; deprecated 'Since OpenSSL 3.0';
  {* Returns 64-bit optimized methods for nistp256
  *  return  EC_METHOD object
  }
  function EC_GFp_nistp256_method: PEC_METHOD; cdecl; external CLibCrypto name 'EC_GFp_nistp256_method'; deprecated 'Since OpenSSL 3.0';
  {* Returns 64-bit optimized methods for nistp521
  *  return  EC_METHOD object
  }
  function EC_GFp_nistp521_method: PEC_METHOD; cdecl; external CLibCrypto name 'EC_GFp_nistp521_method'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM EC_GFp_nistp224_method}
  {$EXTERNALSYM EC_GFp_nistp256_method}
  {$EXTERNALSYM EC_GFp_nistp521_method}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GFp_nistp224_method: PEC_METHOD; cdecl;
  function Load_EC_GFp_nistp256_method: PEC_METHOD; cdecl;
  function Load_EC_GFp_nistp521_method: PEC_METHOD; cdecl;

var
  EC_GFp_nistp224_method: function: PEC_METHOD; cdecl = Load_EC_GFp_nistp224_method;
  {* Returns 64-bit optimized methods for nistp256
  *  return  EC_METHOD object
  }
  EC_GFp_nistp256_method: function: PEC_METHOD; cdecl = Load_EC_GFp_nistp256_method;
  {* Returns 64-bit optimized methods for nistp521
  *  return  EC_METHOD object
  }
  EC_GFp_nistp521_method: function: PEC_METHOD; cdecl = Load_EC_GFp_nistp521_method;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}
      { OPENSSL_NO_EC_NISTP_64_GCC_128 }
      {$ifndef  OPENSSL_NO_EC2M}


        {******************************************************************}
        {           EC_METHOD for curves over GF(2^m)                      }
        {******************************************************************}
        {* Returns the basic GF2m ec method
        *  return  EC_METHOD object
        }
        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GF2m_simple_method: PEC_METHOD; cdecl; external CLibCrypto name 'EC_GF2m_simple_method'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM EC_GF2m_simple_method}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GF2m_simple_method: PEC_METHOD; cdecl;

var
  EC_GF2m_simple_method: function: PEC_METHOD; cdecl = Load_EC_GF2m_simple_method;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}


      {******************************************************************}
      {                   EC_GROUP functions                             }
      {******************************************************************}
      {*
      *  Creates a new EC_GROUP object
      *  param   meth   EC_METHOD to use
      *  return  newly created EC_GROUP object or NULL in case of an error.
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_new(meth: PEC_METHOD): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new'; deprecated 'Since OpenSSL 3.0';
  {* Clears and frees a EC_GROUP object
  *  param  group  EC_GROUP object to be cleared and freed.
  }
  procedure EC_GROUP_clear_free(group: PEC_GROUP); cdecl; external CLibCrypto name 'EC_GROUP_clear_free'; deprecated 'Since OpenSSL 3.0';
  {* Returns the EC_METHOD of the EC_GROUP object.
  *  param  group  EC_GROUP object
  *  return EC_METHOD used in this EC_GROUP object.
  }
  function EC_GROUP_method_of(group: PEC_GROUP): PEC_METHOD; cdecl; external CLibCrypto name 'EC_GROUP_method_of'; deprecated 'Since OpenSSL 3.0';
  {* Returns the field type of the EC_METHOD.
  *  param  meth  EC_METHOD object
  *  return NID of the underlying field type OID.
  }
  function EC_METHOD_get_field_type(meth: PEC_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_METHOD_get_field_type'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_GROUP_new}
  {$EXTERNALSYM EC_GROUP_clear_free}
  {$EXTERNALSYM EC_GROUP_method_of}
  {$EXTERNALSYM EC_METHOD_get_field_type}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_new(meth: PEC_METHOD): PEC_GROUP; cdecl;
  procedure Load_EC_GROUP_clear_free(group: PEC_GROUP); cdecl;
  function Load_EC_GROUP_method_of(group: PEC_GROUP): PEC_METHOD; cdecl;
  function Load_EC_METHOD_get_field_type(meth: PEC_METHOD): TOpenSSL_C_INT; cdecl;

var
  EC_GROUP_new: function(meth: PEC_METHOD): PEC_GROUP; cdecl = Load_EC_GROUP_new;
  {* Clears and frees a EC_GROUP object
  *  param  group  EC_GROUP object to be cleared and freed.
  }
  EC_GROUP_clear_free: procedure(group: PEC_GROUP); cdecl = Load_EC_GROUP_clear_free;
  {* Returns the EC_METHOD of the EC_GROUP object.
  *  param  group  EC_GROUP object
  *  return EC_METHOD used in this EC_GROUP object.
  }
  EC_GROUP_method_of: function(group: PEC_GROUP): PEC_METHOD; cdecl = Load_EC_GROUP_method_of;
  {* Returns the field type of the EC_METHOD.
  *  param  meth  EC_METHOD object
  *  return NID of the underlying field type OID.
  }
  EC_METHOD_get_field_type: function(meth: PEC_METHOD): TOpenSSL_C_INT; cdecl = Load_EC_METHOD_get_field_type;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {* Frees a EC_GROUP object
    *  param  group  EC_GROUP object to be freed.
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_GROUP_free(group: PEC_GROUP); cdecl; external CLibCrypto name 'EC_GROUP_free';
  {* Copies EC_GROUP objects. Note: both EC_GROUPs must use the same EC_METHOD.
  *  param  dst  destination EC_GROUP object
  *  param  src  source EC_GROUP object
  *  return 1 on success and 0 if an error occurred.
  }
  function EC_GROUP_copy(dst: PEC_GROUP; src: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_copy';
  {* Creates a new EC_GROUP object and copies the content
  *  form src to the newly created EC_KEY object
  *  param  src  source EC_GROUP object
  *  return newly created EC_GROUP object or NULL in case of an error.
  }
  function EC_GROUP_dup(src: PEC_GROUP): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_dup';
  {* Sets the generator and its order/cofactor of a EC_GROUP object.
  *  param  group      EC_GROUP object
  *  param  generator  EC_POINT object with the generator.
  *  param  order      the order of the group generated by the generator.
  *  param  cofactor   the index of the sub-group generated by the generator
  *                     in the group of all points on the elliptic curve.
  *  return 1 on success and 0 if an error occurred
  }
  function EC_GROUP_set_generator(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_set_generator';
  {* Returns the generator of a EC_GROUP object.
  *  param  group  EC_GROUP object
  *  return the currently used generator (possibly NULL).
  }
  function EC_GROUP_get0_generator(group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto name 'EC_GROUP_get0_generator';
  {* Returns the montgomery data for order(Generator)
  *  param  group  EC_GROUP object
  *  return the currently used montgomery data (possibly NULL).
  }
  function EC_GROUP_get_mont_data(group: PEC_GROUP): PBN_MONT_CTX; cdecl; external CLibCrypto name 'EC_GROUP_get_mont_data';
  {* Gets the order of a EC_GROUP
  *  param  group  EC_GROUP object
  *  param  order  BIGNUM to which the order is copied
  *  param  ctx    unused
  *  return 1 on success and 0 if an error occurred
  }
  function EC_GROUP_get_order(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_order';
  {* Gets the order of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return the group order
  }
  function EC_GROUP_get0_order(group: PEC_GROUP): PBIGNUM; cdecl; external CLibCrypto name 'EC_GROUP_get0_order';
  {* Gets the number of bits of the order of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return number of bits of group order.
  }
  function EC_GROUP_order_bits(group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_order_bits';
  {* Gets the cofactor of a EC_GROUP
  *  param  group     EC_GROUP object
  *  param  cofactor  BIGNUM to which the cofactor is copied
  *  param  ctx       unused
  *  return 1 on success and 0 if an error occurred
  }
  function EC_GROUP_get_cofactor(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_cofactor';
  {* Gets the cofactor of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return the group cofactor
  }
  function EC_GROUP_get0_cofactor(group: PEC_GROUP): PBIGNUM; cdecl; external CLibCrypto name 'EC_GROUP_get0_cofactor';
  {* Sets the name of a EC_GROUP object
  *  param  group  EC_GROUP object
  *  param  nid    NID of the curve name OID
  }
  procedure EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EC_GROUP_set_curve_name';
  {* Returns the curve name of a EC_GROUP object
  *  param  group  EC_GROUP object
  *  return NID of the curve name OID or 0 if not set.
  }
  function EC_GROUP_get_curve_name(group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_curve_name';
  {* Gets the field of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return the group field
  }
  function EC_GROUP_get0_field(group: PEC_GROUP): PBIGNUM; cdecl; external CLibCrypto name 'EC_GROUP_get0_field';
  {* Returns the field type of the EC_GROUP.
  *  param  group  EC_GROUP object
  *  return NID of the underlying field type OID.
  }
  function EC_GROUP_get_field_type(group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_field_type';
  procedure EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EC_GROUP_set_asn1_flag';
  function EC_GROUP_get_asn1_flag(group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_asn1_flag';
  procedure EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl; external CLibCrypto name 'EC_GROUP_set_point_conversion_form';
  function EC_GROUP_get_point_conversion_form(_param1: PEC_GROUP): Tpoint_conversion_form_t; cdecl; external CLibCrypto name 'EC_GROUP_get_point_conversion_form';
  function EC_GROUP_get0_seed(x: PEC_GROUP): Pbyte; cdecl; external CLibCrypto name 'EC_GROUP_get0_seed';
  function EC_GROUP_get_seed_len(_param1: PEC_GROUP): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_GROUP_get_seed_len';
  function EC_GROUP_set_seed(_param1: PEC_GROUP; _param2: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_GROUP_set_seed';
  {* Sets the parameters of an ec curve defined by y^2 = x^3 + a*x + b (for GFp)
  *  or y^2 + x*y = x^3 + a*x^2 + b (for GF2m)
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM with parameter a of the equation
  *  param  b      BIGNUM with parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_GROUP_set_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_set_curve';
  {* Gets the parameters of the ec curve defined by y^2 = x^3 + a*x + b (for GFp)
  *  or y^2 + x*y = x^3 + a*x^2 + b (for GF2m)
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM for parameter a of the equation
  *  param  b      BIGNUM for parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_GROUP_get_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_curve';
    {$else}
  {$EXTERNALSYM EC_GROUP_free}
  {$EXTERNALSYM EC_GROUP_copy}
  {$EXTERNALSYM EC_GROUP_dup}
  {$EXTERNALSYM EC_GROUP_set_generator}
  {$EXTERNALSYM EC_GROUP_get0_generator}
  {$EXTERNALSYM EC_GROUP_get_mont_data}
  {$EXTERNALSYM EC_GROUP_get_order}
  {$EXTERNALSYM EC_GROUP_get0_order}
  {$EXTERNALSYM EC_GROUP_order_bits}
  {$EXTERNALSYM EC_GROUP_get_cofactor}
  {$EXTERNALSYM EC_GROUP_get0_cofactor}
  {$EXTERNALSYM EC_GROUP_set_curve_name}
  {$EXTERNALSYM EC_GROUP_get_curve_name}
  {$EXTERNALSYM EC_GROUP_get0_field}
  {$EXTERNALSYM EC_GROUP_get_field_type}
  {$EXTERNALSYM EC_GROUP_set_asn1_flag}
  {$EXTERNALSYM EC_GROUP_get_asn1_flag}
  {$EXTERNALSYM EC_GROUP_set_point_conversion_form}
  {$EXTERNALSYM EC_GROUP_get_point_conversion_form}
  {$EXTERNALSYM EC_GROUP_get0_seed}
  {$EXTERNALSYM EC_GROUP_get_seed_len}
  {$EXTERNALSYM EC_GROUP_set_seed}
  {$EXTERNALSYM EC_GROUP_set_curve}
  {$EXTERNALSYM EC_GROUP_get_curve}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_GROUP_free(group: PEC_GROUP); cdecl;
  function Load_EC_GROUP_copy(dst: PEC_GROUP; src: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_dup(src: PEC_GROUP): PEC_GROUP; cdecl;
  function Load_EC_GROUP_set_generator(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get0_generator(group: PEC_GROUP): PEC_POINT; cdecl;
  function Load_EC_GROUP_get_mont_data(group: PEC_GROUP): PBN_MONT_CTX; cdecl;
  function Load_EC_GROUP_get_order(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get0_order(group: PEC_GROUP): PBIGNUM; cdecl;
  function Load_EC_GROUP_order_bits(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get_cofactor(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get0_cofactor(group: PEC_GROUP): PBIGNUM; cdecl;
  procedure Load_EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl;
  function Load_EC_GROUP_get_curve_name(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get0_field(group: PEC_GROUP): PBIGNUM; cdecl;
  function Load_EC_GROUP_get_field_type(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  procedure Load_EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl;
  function Load_EC_GROUP_get_asn1_flag(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  procedure Load_EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl;
  function Load_EC_GROUP_get_point_conversion_form(_param1: PEC_GROUP): Tpoint_conversion_form_t; cdecl;
  function Load_EC_GROUP_get0_seed(x: PEC_GROUP): Pbyte; cdecl;
  function Load_EC_GROUP_get_seed_len(_param1: PEC_GROUP): TOpenSSL_C_SIZET; cdecl;
  function Load_EC_GROUP_set_seed(_param1: PEC_GROUP; _param2: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
  function Load_EC_GROUP_set_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_GROUP_free: procedure(group: PEC_GROUP); cdecl = Load_EC_GROUP_free;
  {* Copies EC_GROUP objects. Note: both EC_GROUPs must use the same EC_METHOD.
  *  param  dst  destination EC_GROUP object
  *  param  src  source EC_GROUP object
  *  return 1 on success and 0 if an error occurred.
  }
  EC_GROUP_copy: function(dst: PEC_GROUP; src: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_copy;
  {* Creates a new EC_GROUP object and copies the content
  *  form src to the newly created EC_KEY object
  *  param  src  source EC_GROUP object
  *  return newly created EC_GROUP object or NULL in case of an error.
  }
  EC_GROUP_dup: function(src: PEC_GROUP): PEC_GROUP; cdecl = Load_EC_GROUP_dup;
  {* Sets the generator and its order/cofactor of a EC_GROUP object.
  *  param  group      EC_GROUP object
  *  param  generator  EC_POINT object with the generator.
  *  param  order      the order of the group generated by the generator.
  *  param  cofactor   the index of the sub-group generated by the generator
  *                     in the group of all points on the elliptic curve.
  *  return 1 on success and 0 if an error occurred
  }
  EC_GROUP_set_generator: function(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_generator;
  {* Returns the generator of a EC_GROUP object.
  *  param  group  EC_GROUP object
  *  return the currently used generator (possibly NULL).
  }
  EC_GROUP_get0_generator: function(group: PEC_GROUP): PEC_POINT; cdecl = Load_EC_GROUP_get0_generator;
  {* Returns the montgomery data for order(Generator)
  *  param  group  EC_GROUP object
  *  return the currently used montgomery data (possibly NULL).
  }
  EC_GROUP_get_mont_data: function(group: PEC_GROUP): PBN_MONT_CTX; cdecl = Load_EC_GROUP_get_mont_data;
  {* Gets the order of a EC_GROUP
  *  param  group  EC_GROUP object
  *  param  order  BIGNUM to which the order is copied
  *  param  ctx    unused
  *  return 1 on success and 0 if an error occurred
  }
  EC_GROUP_get_order: function(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_order;
  {* Gets the order of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return the group order
  }
  EC_GROUP_get0_order: function(group: PEC_GROUP): PBIGNUM; cdecl = Load_EC_GROUP_get0_order;
  {* Gets the number of bits of the order of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return number of bits of group order.
  }
  EC_GROUP_order_bits: function(group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_order_bits;
  {* Gets the cofactor of a EC_GROUP
  *  param  group     EC_GROUP object
  *  param  cofactor  BIGNUM to which the cofactor is copied
  *  param  ctx       unused
  *  return 1 on success and 0 if an error occurred
  }
  EC_GROUP_get_cofactor: function(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_cofactor;
  {* Gets the cofactor of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return the group cofactor
  }
  EC_GROUP_get0_cofactor: function(group: PEC_GROUP): PBIGNUM; cdecl = Load_EC_GROUP_get0_cofactor;
  {* Sets the name of a EC_GROUP object
  *  param  group  EC_GROUP object
  *  param  nid    NID of the curve name OID
  }
  EC_GROUP_set_curve_name: procedure(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl = Load_EC_GROUP_set_curve_name;
  {* Returns the curve name of a EC_GROUP object
  *  param  group  EC_GROUP object
  *  return NID of the curve name OID or 0 if not set.
  }
  EC_GROUP_get_curve_name: function(group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve_name;
  {* Gets the field of an EC_GROUP
  *  param  group  EC_GROUP object
  *  return the group field
  }
  EC_GROUP_get0_field: function(group: PEC_GROUP): PBIGNUM; cdecl = Load_EC_GROUP_get0_field;
  {* Returns the field type of the EC_GROUP.
  *  param  group  EC_GROUP object
  *  return NID of the underlying field type OID.
  }
  EC_GROUP_get_field_type: function(group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_field_type;
  EC_GROUP_set_asn1_flag: procedure(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl = Load_EC_GROUP_set_asn1_flag;
  EC_GROUP_get_asn1_flag: function(group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_asn1_flag;
  EC_GROUP_set_point_conversion_form: procedure(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl = Load_EC_GROUP_set_point_conversion_form;
  EC_GROUP_get_point_conversion_form: function(_param1: PEC_GROUP): Tpoint_conversion_form_t; cdecl = Load_EC_GROUP_get_point_conversion_form;
  EC_GROUP_get0_seed: function(x: PEC_GROUP): Pbyte; cdecl = Load_EC_GROUP_get0_seed;
  EC_GROUP_get_seed_len: function(_param1: PEC_GROUP): TOpenSSL_C_SIZET; cdecl = Load_EC_GROUP_get_seed_len;
  EC_GROUP_set_seed: function(_param1: PEC_GROUP; _param2: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_EC_GROUP_set_seed;
  {* Sets the parameters of an ec curve defined by y^2 = x^3 + a*x + b (for GFp)
  *  or y^2 + x*y = x^3 + a*x^2 + b (for GF2m)
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM with parameter a of the equation
  *  param  b      BIGNUM with parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_GROUP_set_curve: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_curve;
  {* Gets the parameters of the ec curve defined by y^2 = x^3 + a*x + b (for GFp)
  *  or y^2 + x*y = x^3 + a*x^2 + b (for GF2m)
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM for parameter a of the equation
  *  param  b      BIGNUM for parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_GROUP_get_curve: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {* Sets the parameters of an ec curve. Synonym for EC_GROUP_set_curve
      *  param  group  EC_GROUP object
      *  param  p      BIGNUM with the prime number (GFp) or the polynomial
      *                 defining the underlying field (GF2m)
      *  param  a      BIGNUM with parameter a of the equation
      *  param  b      BIGNUM with parameter b of the equation
      *  param  ctx    BN_CTX object (optional)
      *  return 1 on success and 0 if an error occurred
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_set_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_set_curve_GFp'; deprecated 'Since OpenSSL 3.0';
  {* Gets the parameters of an ec curve. Synonym for EC_GROUP_get_curve
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM for parameter a of the equation
  *  param  b      BIGNUM for parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_GROUP_get_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_curve_GFp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_GROUP_set_curve_GFp}
  {$EXTERNALSYM EC_GROUP_get_curve_GFp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_set_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_GROUP_set_curve_GFp: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_curve_GFp;
  {* Gets the parameters of an ec curve. Synonym for EC_GROUP_get_curve
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM for parameter a of the equation
  *  param  b      BIGNUM for parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_GROUP_get_curve_GFp: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve_GFp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$ifndef  OPENSSL_NO_EC2M}


        {* Sets the parameter of an ec curve. Synonym for EC_GROUP_set_curve
        *  param  group  EC_GROUP object
        *  param  p      BIGNUM with the prime number (GFp) or the polynomial
        *                 defining the underlying field (GF2m)
        *  param  a      BIGNUM with parameter a of the equation
        *  param  b      BIGNUM with parameter b of the equation
        *  param  ctx    BN_CTX object (optional)
        *  return 1 on success and 0 if an error occurred
        }
        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_set_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_set_curve_GF2m'; deprecated 'Since OpenSSL 3.0';
  {* Gets the parameters of an ec curve. Synonym for EC_GROUP_get_curve
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM for parameter a of the equation
  *  param  b      BIGNUM for parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_GROUP_get_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_curve_GF2m'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM EC_GROUP_set_curve_GF2m}
  {$EXTERNALSYM EC_GROUP_get_curve_GF2m}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_set_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_GROUP_set_curve_GF2m: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_curve_GF2m;
  {* Gets the parameters of an ec curve. Synonym for EC_GROUP_get_curve
  *  param  group  EC_GROUP object
  *  param  p      BIGNUM with the prime number (GFp) or the polynomial
  *                 defining the underlying field (GF2m)
  *  param  a      BIGNUM for parameter a of the equation
  *  param  b      BIGNUM for parameter b of the equation
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_GROUP_get_curve_GF2m: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve_GF2m;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}
      { OPENSSL_NO_EC2M }
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {* Returns the number of bits needed to represent a field element
    *  param  group  EC_GROUP object
    *  return number of bits needed to represent a field element
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_get_degree(group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_degree';
  {* Checks whether the parameter in the EC_GROUP define a valid ec group
  *  param  group  EC_GROUP object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if group is a valid ec group and 0 otherwise
  }
  function EC_GROUP_check(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_check';
  {* Checks whether the discriminant of the elliptic curve is zero or not
  *  param  group  EC_GROUP object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if the discriminant is not zero and 0 otherwise
  }
  function EC_GROUP_check_discriminant(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_check_discriminant';
  {* Compares two EC_GROUP objects
  *  param  a    first EC_GROUP object
  *  param  b    second EC_GROUP object
  *  param  ctx  BN_CTX object (optional)
  *  return 0 if the groups are equal, 1 if not, or -1 on error
  }
  function EC_GROUP_cmp(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_cmp';
  
  {* EC_GROUP_new_GF*() calls EC_GROUP_new() and EC_GROUP_set_GF*() after
  * choosing an appropriate EC_METHOD
  }
  {* Creates a new EC_GROUP object with the specified parameters defined
  *  over GFp (defined by the equation y^2 = x^3 + a*x + b)
  *  param  p    BIGNUM with the prime number
  *  param  a    BIGNUM with the parameter a of the equation
  *  param  b    BIGNUM with the parameter b of the equation
  *  param  ctx  BN_CTX object (optional)
  *  return newly created EC_GROUP object with the specified parameters
  }
  function EC_GROUP_new_curve_GFp(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new_curve_GFp';
    {$else}
  {$EXTERNALSYM EC_GROUP_get_degree}
  {$EXTERNALSYM EC_GROUP_check}
  {$EXTERNALSYM EC_GROUP_check_discriminant}
  {$EXTERNALSYM EC_GROUP_cmp}
  {$EXTERNALSYM EC_GROUP_new_curve_GFp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_get_degree(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_check(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_check_discriminant(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_cmp(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_new_curve_GFp(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;

var
  EC_GROUP_get_degree: function(group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_degree;
  {* Checks whether the parameter in the EC_GROUP define a valid ec group
  *  param  group  EC_GROUP object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if group is a valid ec group and 0 otherwise
  }
  EC_GROUP_check: function(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_check;
  {* Checks whether the discriminant of the elliptic curve is zero or not
  *  param  group  EC_GROUP object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if the discriminant is not zero and 0 otherwise
  }
  EC_GROUP_check_discriminant: function(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_check_discriminant;
  {* Compares two EC_GROUP objects
  *  param  a    first EC_GROUP object
  *  param  b    second EC_GROUP object
  *  param  ctx  BN_CTX object (optional)
  *  return 0 if the groups are equal, 1 if not, or -1 on error
  }
  EC_GROUP_cmp: function(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_cmp;
  
  {* EC_GROUP_new_GF*() calls EC_GROUP_new() and EC_GROUP_set_GF*() after
  * choosing an appropriate EC_METHOD
  }
  {* Creates a new EC_GROUP object with the specified parameters defined
  *  over GFp (defined by the equation y^2 = x^3 + a*x + b)
  *  param  p    BIGNUM with the prime number
  *  param  a    BIGNUM with the parameter a of the equation
  *  param  b    BIGNUM with the parameter b of the equation
  *  param  ctx  BN_CTX object (optional)
  *  return newly created EC_GROUP object with the specified parameters
  }
  EC_GROUP_new_curve_GFp: function(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = Load_EC_GROUP_new_curve_GFp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_EC2M}


      {* Creates a new EC_GROUP object with the specified parameters defined
      *  over GF2m (defined by the equation y^2 + x*y = x^3 + a*x^2 + b)
      *  param  p    BIGNUM with the polynomial defining the underlying field
      *  param  a    BIGNUM with the parameter a of the equation
      *  param  b    BIGNUM with the parameter b of the equation
      *  param  ctx  BN_CTX object (optional)
      *  return newly created EC_GROUP object with the specified parameters
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_new_curve_GF2m(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new_curve_GF2m';
      {$else}
  {$EXTERNALSYM EC_GROUP_new_curve_GF2m}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_new_curve_GF2m(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;

var
  EC_GROUP_new_curve_GF2m: function(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = Load_EC_GROUP_new_curve_GF2m;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {*
    * Creates a EC_GROUP object with a curve specified by parameters.
    * The parameters may be explicit or a named curve,
    *  param  params A list of parameters describing the group.
    *  param  libctx The associated library context or NULL for the default
    *                 context
    *  param  propq  A property query string
    *  return newly created EC_GROUP object with specified parameters or NULL
    *          if an error occurred
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_new_from_params(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new_from_params';
  {*
  * Creates a EC_GROUP object with a curve specified by a NID
  *  param  libctx The associated library context or NULL for the default
  *                 context
  *  param  propq  A property query string
  *  param  nid    NID of the OID of the curve name
  *  return newly created EC_GROUP object with specified curve or NULL
  *          if an error occurred
  }
  function EC_GROUP_new_by_curve_name_ex(libctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new_by_curve_name_ex';
  {*
  * Creates a EC_GROUP object with a curve specified by a NID. Same as
  * EC_GROUP_new_by_curve_name_ex but the libctx and propq are always
  * NULL.
  *  param  nid    NID of the OID of the curve name
  *  return newly created EC_GROUP object with specified curve or NULL
  *          if an error occurred
  }
  function EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new_by_curve_name';
  {* Creates a new EC_GROUP object from an ECPARAMETERS object
  *  param  params  pointer to the ECPARAMETERS object
  *  return newly created EC_GROUP object with specified curve or NULL
  *          if an error occurred
  }
  function EC_GROUP_new_from_ecparameters(params: PECPARAMETERS): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new_from_ecparameters';
  {* Creates an ECPARAMETERS object for the given EC_GROUP object.
  *  param  group   pointer to the EC_GROUP object
  *  param  params  pointer to an existing ECPARAMETERS object or NULL
  *  return pointer to the new ECPARAMETERS object or NULL
  *          if an error occurred.
  }
  function EC_GROUP_get_ecparameters(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl; external CLibCrypto name 'EC_GROUP_get_ecparameters';
  {* Creates a new EC_GROUP object from an ECPKPARAMETERS object
  *  param  params  pointer to an existing ECPKPARAMETERS object, or NULL
  *  return newly created EC_GROUP object with specified curve, or NULL
  *          if an error occurred
  }
  function EC_GROUP_new_from_ecpkparameters(params: PECPKPARAMETERS): PEC_GROUP; cdecl; external CLibCrypto name 'EC_GROUP_new_from_ecpkparameters';
  {* Creates an ECPKPARAMETERS object for the given EC_GROUP object.
  *  param  group   pointer to the EC_GROUP object
  *  param  params  pointer to an existing ECPKPARAMETERS object or NULL
  *  return pointer to the new ECPKPARAMETERS object or NULL
  *          if an error occurred.
  }
  function EC_GROUP_get_ecpkparameters(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl; external CLibCrypto name 'EC_GROUP_get_ecpkparameters';
  {******************************************************************}
  {               handling of internal curves                        }
  {******************************************************************}
    {$else}
  {$EXTERNALSYM EC_GROUP_new_from_params}
  {$EXTERNALSYM EC_GROUP_new_by_curve_name_ex}
  {$EXTERNALSYM EC_GROUP_new_by_curve_name}
  {$EXTERNALSYM EC_GROUP_new_from_ecparameters}
  {$EXTERNALSYM EC_GROUP_get_ecparameters}
  {$EXTERNALSYM EC_GROUP_new_from_ecpkparameters}
  {$EXTERNALSYM EC_GROUP_get_ecpkparameters}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_new_from_params(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_GROUP; cdecl;
  function Load_EC_GROUP_new_by_curve_name_ex(libctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_GROUP; cdecl;
  function Load_EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl;
  function Load_EC_GROUP_new_from_ecparameters(params: PECPARAMETERS): PEC_GROUP; cdecl;
  function Load_EC_GROUP_get_ecparameters(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl;
  function Load_EC_GROUP_new_from_ecpkparameters(params: PECPKPARAMETERS): PEC_GROUP; cdecl;
  function Load_EC_GROUP_get_ecpkparameters(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl;

var
  EC_GROUP_new_from_params: function(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_GROUP; cdecl = Load_EC_GROUP_new_from_params;
  {*
  * Creates a EC_GROUP object with a curve specified by a NID
  *  param  libctx The associated library context or NULL for the default
  *                 context
  *  param  propq  A property query string
  *  param  nid    NID of the OID of the curve name
  *  return newly created EC_GROUP object with specified curve or NULL
  *          if an error occurred
  }
  EC_GROUP_new_by_curve_name_ex: function(libctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_GROUP; cdecl = Load_EC_GROUP_new_by_curve_name_ex;
  {*
  * Creates a EC_GROUP object with a curve specified by a NID. Same as
  * EC_GROUP_new_by_curve_name_ex but the libctx and propq are always
  * NULL.
  *  param  nid    NID of the OID of the curve name
  *  return newly created EC_GROUP object with specified curve or NULL
  *          if an error occurred
  }
  EC_GROUP_new_by_curve_name: function(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl = Load_EC_GROUP_new_by_curve_name;
  {* Creates a new EC_GROUP object from an ECPARAMETERS object
  *  param  params  pointer to the ECPARAMETERS object
  *  return newly created EC_GROUP object with specified curve or NULL
  *          if an error occurred
  }
  EC_GROUP_new_from_ecparameters: function(params: PECPARAMETERS): PEC_GROUP; cdecl = Load_EC_GROUP_new_from_ecparameters;
  {* Creates an ECPARAMETERS object for the given EC_GROUP object.
  *  param  group   pointer to the EC_GROUP object
  *  param  params  pointer to an existing ECPARAMETERS object or NULL
  *  return pointer to the new ECPARAMETERS object or NULL
  *          if an error occurred.
  }
  EC_GROUP_get_ecparameters: function(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl = Load_EC_GROUP_get_ecparameters;
  {* Creates a new EC_GROUP object from an ECPKPARAMETERS object
  *  param  params  pointer to an existing ECPKPARAMETERS object, or NULL
  *  return newly created EC_GROUP object with specified curve, or NULL
  *          if an error occurred
  }
  EC_GROUP_new_from_ecpkparameters: function(params: PECPKPARAMETERS): PEC_GROUP; cdecl = Load_EC_GROUP_new_from_ecpkparameters;
  {* Creates an ECPKPARAMETERS object for the given EC_GROUP object.
  *  param  group   pointer to the EC_GROUP object
  *  param  params  pointer to an existing ECPKPARAMETERS object or NULL
  *  return pointer to the new ECPKPARAMETERS object or NULL
  *          if an error occurred.
  }
  EC_GROUP_get_ecpkparameters: function(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl = Load_EC_GROUP_get_ecpkparameters;
  {******************************************************************}
  {               handling of internal curves                        }
  {******************************************************************}
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PEC_builtin_curve = ^TEC_builtin_curve;
  PPEC_builtin_curve = ^PEC_builtin_curve;
  {end of auto-generated forward references}

  TEC_builtin_curve = record 
    nid: TOpenSSL_C_INT;
    comment: PAnsiChar;
  end;


    
    {* EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number of all
    * available curves or zero if a error occurred. In case r is not zero,
    * nitems EC_builtin_curve structures are filled with the data of the first
    * nitems internal groups
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_get_builtin_curves';
  function EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'EC_curve_nid2nist';
  function EC_curve_nist2nid(name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_curve_nist2nid';
  function EC_GROUP_check_named_curve(group: PEC_GROUP; nist_only: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_check_named_curve';
  {******************************************************************}
  {                    EC_POINT functions                            }
  {******************************************************************}
  {* Creates a new EC_POINT object for the specified EC_GROUP
  *  param  group  EC_GROUP the underlying EC_GROUP object
  *  return newly created EC_POINT object or NULL if an error occurred
  }
  function EC_POINT_new(group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto name 'EC_POINT_new';
  {* Frees a EC_POINT object
  *  param  point  EC_POINT object to be freed
  }
  procedure EC_POINT_free(point: PEC_POINT); cdecl; external CLibCrypto name 'EC_POINT_free';
  {* Clears and frees a EC_POINT object
  *  param  point  EC_POINT object to be cleared and freed
  }
  procedure EC_POINT_clear_free(point: PEC_POINT); cdecl; external CLibCrypto name 'EC_POINT_clear_free';
  {* Copies EC_POINT object
  *  param  dst  destination EC_POINT object
  *  param  src  source EC_POINT object
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_copy(dst: PEC_POINT; src: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_copy';
  {* Creates a new EC_POINT object and copies the content of the supplied
  *  EC_POINT
  *  param  src    source EC_POINT object
  *  param  group  underlying the EC_GROUP object
  *  return newly created EC_POINT object or NULL if an error occurred
  }
  function EC_POINT_dup(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto name 'EC_POINT_dup';
  {* Sets a point to infinity (neutral element)
  *  param  group  underlying EC_GROUP object
  *  param  point  EC_POINT to set to infinity
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_set_to_infinity(group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_to_infinity';
    {$else}
  {$EXTERNALSYM EC_get_builtin_curves}
  {$EXTERNALSYM EC_curve_nid2nist}
  {$EXTERNALSYM EC_curve_nist2nid}
  {$EXTERNALSYM EC_GROUP_check_named_curve}
  {$EXTERNALSYM EC_POINT_new}
  {$EXTERNALSYM EC_POINT_free}
  {$EXTERNALSYM EC_POINT_clear_free}
  {$EXTERNALSYM EC_POINT_copy}
  {$EXTERNALSYM EC_POINT_dup}
  {$EXTERNALSYM EC_POINT_set_to_infinity}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
  function Load_EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl;
  function Load_EC_curve_nist2nid(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_check_named_curve(group: PEC_GROUP; nist_only: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_new(group: PEC_GROUP): PEC_POINT; cdecl;
  procedure Load_EC_POINT_free(point: PEC_POINT); cdecl;
  procedure Load_EC_POINT_clear_free(point: PEC_POINT); cdecl;
  function Load_EC_POINT_copy(dst: PEC_POINT; src: PEC_POINT): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_dup(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl;
  function Load_EC_POINT_set_to_infinity(group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl;

var
  EC_get_builtin_curves: function(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_EC_get_builtin_curves;
  EC_curve_nid2nist: function(nid: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_EC_curve_nid2nist;
  EC_curve_nist2nid: function(name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EC_curve_nist2nid;
  EC_GROUP_check_named_curve: function(group: PEC_GROUP; nist_only: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_check_named_curve;
  {******************************************************************}
  {                    EC_POINT functions                            }
  {******************************************************************}
  {* Creates a new EC_POINT object for the specified EC_GROUP
  *  param  group  EC_GROUP the underlying EC_GROUP object
  *  return newly created EC_POINT object or NULL if an error occurred
  }
  EC_POINT_new: function(group: PEC_GROUP): PEC_POINT; cdecl = Load_EC_POINT_new;
  {* Frees a EC_POINT object
  *  param  point  EC_POINT object to be freed
  }
  EC_POINT_free: procedure(point: PEC_POINT); cdecl = Load_EC_POINT_free;
  {* Clears and frees a EC_POINT object
  *  param  point  EC_POINT object to be cleared and freed
  }
  EC_POINT_clear_free: procedure(point: PEC_POINT); cdecl = Load_EC_POINT_clear_free;
  {* Copies EC_POINT object
  *  param  dst  destination EC_POINT object
  *  param  src  source EC_POINT object
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_copy: function(dst: PEC_POINT; src: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_POINT_copy;
  {* Creates a new EC_POINT object and copies the content of the supplied
  *  EC_POINT
  *  param  src    source EC_POINT object
  *  param  group  underlying the EC_GROUP object
  *  return newly created EC_POINT object or NULL if an error occurred
  }
  EC_POINT_dup: function(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl = Load_EC_POINT_dup;
  {* Sets a point to infinity (neutral element)
  *  param  group  underlying EC_GROUP object
  *  param  point  EC_POINT to set to infinity
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_set_to_infinity: function(group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_to_infinity;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {* Returns the EC_METHOD used in EC_POINT object
      *  param  point  EC_POINT object
      *  return the EC_METHOD used
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_method_of(point: PEC_POINT): PEC_METHOD; cdecl; external CLibCrypto name 'EC_POINT_method_of'; deprecated 'Since OpenSSL 3.0';
  {* Sets the jacobian projective coordinates of a EC_POINT over GFp
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM with the x-coordinate
  *  param  y      BIGNUM with the y-coordinate
  *  param  z      BIGNUM with the z-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_set_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_Jprojective_coordinates_GFp'; deprecated 'Since OpenSSL 3.0';
  {* Gets the jacobian projective coordinates of a EC_POINT over GFp
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  z      BIGNUM for the z-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_get_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_get_Jprojective_coordinates_GFp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_POINT_method_of}
  {$EXTERNALSYM EC_POINT_set_Jprojective_coordinates_GFp}
  {$EXTERNALSYM EC_POINT_get_Jprojective_coordinates_GFp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_method_of(point: PEC_POINT): PEC_METHOD; cdecl;
  function Load_EC_POINT_set_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_get_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_method_of: function(point: PEC_POINT): PEC_METHOD; cdecl = Load_EC_POINT_method_of;
  {* Sets the jacobian projective coordinates of a EC_POINT over GFp
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM with the x-coordinate
  *  param  y      BIGNUM with the y-coordinate
  *  param  z      BIGNUM with the z-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_set_Jprojective_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_Jprojective_coordinates_GFp;
  {* Gets the jacobian projective coordinates of a EC_POINT over GFp
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  z      BIGNUM for the z-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_get_Jprojective_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_Jprojective_coordinates_GFp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {* Sets the affine coordinates of an EC_POINT
    *  param  group  underlying EC_GROUP object
    *  param  p      EC_POINT object
    *  param  x      BIGNUM with the x-coordinate
    *  param  y      BIGNUM with the y-coordinate
    *  param  ctx    BN_CTX object (optional)
    *  return 1 on success and 0 if an error occurred
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_set_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_affine_coordinates';
  {* Gets the affine coordinates of an EC_POINT.
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_get_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_get_affine_coordinates';
    {$else}
  {$EXTERNALSYM EC_POINT_set_affine_coordinates}
  {$EXTERNALSYM EC_POINT_get_affine_coordinates}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_set_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_get_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_set_affine_coordinates: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_affine_coordinates;
  {* Gets the affine coordinates of an EC_POINT.
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_get_affine_coordinates: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_affine_coordinates;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {* Sets the affine coordinates of an EC_POINT. A synonym of
      *  EC_POINT_set_affine_coordinates
      *  param  group  underlying EC_GROUP object
      *  param  p      EC_POINT object
      *  param  x      BIGNUM with the x-coordinate
      *  param  y      BIGNUM with the y-coordinate
      *  param  ctx    BN_CTX object (optional)
      *  return 1 on success and 0 if an error occurred
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_set_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_affine_coordinates_GFp'; deprecated 'Since OpenSSL 3.0';
  {* Gets the affine coordinates of an EC_POINT. A synonym of
  *  EC_POINT_get_affine_coordinates
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_get_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_get_affine_coordinates_GFp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GFp}
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GFp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_set_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_get_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_set_affine_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_affine_coordinates_GFp;
  {* Gets the affine coordinates of an EC_POINT. A synonym of
  *  EC_POINT_get_affine_coordinates
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_get_affine_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_affine_coordinates_GFp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {* Sets the x9.62 compressed coordinates of a EC_POINT
    *  param  group  underlying EC_GROUP object
    *  param  p      EC_POINT object
    *  param  x      BIGNUM with x-coordinate
    *  param  y_bit  integer with the y-Bit (either 0 or 1)
    *  param  ctx    BN_CTX object (optional)
    *  return 1 on success and 0 if an error occurred
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_set_compressed_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_compressed_coordinates';
    {$else}
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_set_compressed_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_set_compressed_coordinates: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_compressed_coordinates;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {* Sets the x9.62 compressed coordinates of a EC_POINT. A synonym of
      *  EC_POINT_set_compressed_coordinates
      *  param  group  underlying EC_GROUP object
      *  param  p      EC_POINT object
      *  param  x      BIGNUM with x-coordinate
      *  param  y_bit  integer with the y-Bit (either 0 or 1)
      *  param  ctx    BN_CTX object (optional)
      *  return 1 on success and 0 if an error occurred
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_set_compressed_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_compressed_coordinates_GFp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GFp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_set_compressed_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_set_compressed_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_compressed_coordinates_GFp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$ifndef  OPENSSL_NO_EC2M}


        {* Sets the affine coordinates of an EC_POINT. A synonym of
        *  EC_POINT_set_affine_coordinates
        *  param  group  underlying EC_GROUP object
        *  param  p      EC_POINT object
        *  param  x      BIGNUM with the x-coordinate
        *  param  y      BIGNUM with the y-coordinate
        *  param  ctx    BN_CTX object (optional)
        *  return 1 on success and 0 if an error occurred
        }
        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_set_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_affine_coordinates_GF2m'; deprecated 'Since OpenSSL 3.0';
  {* Gets the affine coordinates of an EC_POINT. A synonym of
  *  EC_POINT_get_affine_coordinates
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_get_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_get_affine_coordinates_GF2m'; deprecated 'Since OpenSSL 3.0';
  {* Sets the x9.62 compressed coordinates of a EC_POINT. A synonym of
  *  EC_POINT_set_compressed_coordinates
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM with x-coordinate
  *  param  y_bit  integer with the y-Bit (either 0 or 1)
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_set_compressed_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_set_compressed_coordinates_GF2m'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GF2m}
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GF2m}
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GF2m}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_set_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_get_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_set_compressed_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_set_affine_coordinates_GF2m: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_affine_coordinates_GF2m;
  {* Gets the affine coordinates of an EC_POINT. A synonym of
  *  EC_POINT_get_affine_coordinates
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM for the x-coordinate
  *  param  y      BIGNUM for the y-coordinate
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_get_affine_coordinates_GF2m: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_affine_coordinates_GF2m;
  {* Sets the x9.62 compressed coordinates of a EC_POINT. A synonym of
  *  EC_POINT_set_compressed_coordinates
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  x      BIGNUM with x-coordinate
  *  param  y_bit  integer with the y-Bit (either 0 or 1)
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_set_compressed_coordinates_GF2m: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_compressed_coordinates_GF2m;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {* Encodes a EC_POINT object to a octet string
    *  param  group  underlying EC_GROUP object
    *  param  p      EC_POINT object
    *  param  form   point conversion form
    *  param  buf    memory buffer for the result. If NULL the function returns
    *                 required buffer size.
    *  param  len    length of the memory buffer
    *  param  ctx    BN_CTX object (optional)
    *  return the length of the encoded octet string or 0 if an error occurred
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_point2oct(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_POINT_point2oct';
  {* Decodes a EC_POINT from a octet string
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  buf    memory buffer with the encoded ec point
  *  param  len    length of the encoded ec point
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_oct2point(group: PEC_GROUP; p: PEC_POINT; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_oct2point';
  {* Encodes an EC_POINT object to an allocated octet string
  *  param  group  underlying EC_GROUP object
  *  param  point  EC_POINT object
  *  param  form   point conversion form
  *  param  pbuf   returns pointer to allocated buffer
  *  param  ctx    BN_CTX object (optional)
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  function EC_POINT_point2buf(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_POINT_point2buf';
  { other interfaces to point2oct/oct2point: }
    {$else}
  {$EXTERNALSYM EC_POINT_point2oct}
  {$EXTERNALSYM EC_POINT_oct2point}
  {$EXTERNALSYM EC_POINT_point2buf}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_point2oct(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
  function Load_EC_POINT_oct2point(group: PEC_GROUP; p: PEC_POINT; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_point2buf(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;

var
  EC_POINT_point2oct: function(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = Load_EC_POINT_point2oct;
  {* Decodes a EC_POINT from a octet string
  *  param  group  underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  param  buf    memory buffer with the encoded ec point
  *  param  len    length of the encoded ec point
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_oct2point: function(group: PEC_GROUP; p: PEC_POINT; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_oct2point;
  {* Encodes an EC_POINT object to an allocated octet string
  *  param  group  underlying EC_GROUP object
  *  param  point  EC_POINT object
  *  param  form   point conversion form
  *  param  pbuf   returns pointer to allocated buffer
  *  param  ctx    BN_CTX object (optional)
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  EC_POINT_point2buf: function(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = Load_EC_POINT_point2buf;
  { other interfaces to point2oct/oct2point: }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_point2bn(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBIGNUM; _param5: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto name 'EC_POINT_point2bn'; deprecated 'Since OpenSSL 3.0';
  function EC_POINT_bn2point(_param1: PEC_GROUP; _param2: PBIGNUM; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl; external CLibCrypto name 'EC_POINT_bn2point'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_POINT_point2bn}
  {$EXTERNALSYM EC_POINT_bn2point}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_point2bn(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBIGNUM; _param5: PBN_CTX): PBIGNUM; cdecl;
  function Load_EC_POINT_bn2point(_param1: PEC_GROUP; _param2: PBIGNUM; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl;

var
  EC_POINT_point2bn: function(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBIGNUM; _param5: PBN_CTX): PBIGNUM; cdecl = Load_EC_POINT_point2bn;
  EC_POINT_bn2point: function(_param1: PEC_GROUP; _param2: PBIGNUM; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl = Load_EC_POINT_bn2point;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_point2hex(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBN_CTX): PAnsiChar; cdecl; external CLibCrypto name 'EC_POINT_point2hex';
  function EC_POINT_hex2point(_param1: PEC_GROUP; _param2: PAnsiChar; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl; external CLibCrypto name 'EC_POINT_hex2point';
  {******************************************************************}
  {         functions for doing EC_POINT arithmetic                  }
  {******************************************************************}
  {* Computes the sum of two EC_POINT
  *  param  group  underlying EC_GROUP object
  *  param  r      EC_POINT object for the result (r = a + b)
  *  param  a      EC_POINT object with the first summand
  *  param  b      EC_POINT object with the second summand
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_add(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_add';
  {* Computes the double of a EC_POINT
  *  param  group  underlying EC_GROUP object
  *  param  r      EC_POINT object for the result (r = 2 * a)
  *  param  a      EC_POINT object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_dbl(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_dbl';
  {* Computes the inverse of a EC_POINT
  *  param  group  underlying EC_GROUP object
  *  param  a      EC_POINT object to be inverted (it's used for the result as well)
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_POINT_invert(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_invert';
  {* Checks whether the point is the neutral element of the group
  *  param  group  the underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  return 1 if the point is the neutral element and 0 otherwise
  }
  function EC_POINT_is_at_infinity(group: PEC_GROUP; p: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_is_at_infinity';
  {* Checks whether the point is on the curve
  *  param  group  underlying EC_GROUP object
  *  param  point  EC_POINT object to check
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if the point is on the curve, 0 if not, or -1 on error
  }
  function EC_POINT_is_on_curve(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_is_on_curve';
  {* Compares two EC_POINTs
  *  param  group  underlying EC_GROUP object
  *  param  a      first EC_POINT object
  *  param  b      second EC_POINT object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if the points are not equal, 0 if they are, or -1 on error
  }
  function EC_POINT_cmp(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_cmp';
    {$else}
  {$EXTERNALSYM EC_POINT_point2hex}
  {$EXTERNALSYM EC_POINT_hex2point}
  {$EXTERNALSYM EC_POINT_add}
  {$EXTERNALSYM EC_POINT_dbl}
  {$EXTERNALSYM EC_POINT_invert}
  {$EXTERNALSYM EC_POINT_is_at_infinity}
  {$EXTERNALSYM EC_POINT_is_on_curve}
  {$EXTERNALSYM EC_POINT_cmp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_point2hex(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBN_CTX): PAnsiChar; cdecl;
  function Load_EC_POINT_hex2point(_param1: PEC_GROUP; _param2: PAnsiChar; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl;
  function Load_EC_POINT_add(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_dbl(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_invert(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_is_at_infinity(group: PEC_GROUP; p: PEC_POINT): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_is_on_curve(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINT_cmp(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_point2hex: function(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBN_CTX): PAnsiChar; cdecl = Load_EC_POINT_point2hex;
  EC_POINT_hex2point: function(_param1: PEC_GROUP; _param2: PAnsiChar; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl = Load_EC_POINT_hex2point;
  {******************************************************************}
  {         functions for doing EC_POINT arithmetic                  }
  {******************************************************************}
  {* Computes the sum of two EC_POINT
  *  param  group  underlying EC_GROUP object
  *  param  r      EC_POINT object for the result (r = a + b)
  *  param  a      EC_POINT object with the first summand
  *  param  b      EC_POINT object with the second summand
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_add: function(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_add;
  {* Computes the double of a EC_POINT
  *  param  group  underlying EC_GROUP object
  *  param  r      EC_POINT object for the result (r = 2 * a)
  *  param  a      EC_POINT object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_dbl: function(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_dbl;
  {* Computes the inverse of a EC_POINT
  *  param  group  underlying EC_GROUP object
  *  param  a      EC_POINT object to be inverted (it's used for the result as well)
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_POINT_invert: function(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_invert;
  {* Checks whether the point is the neutral element of the group
  *  param  group  the underlying EC_GROUP object
  *  param  p      EC_POINT object
  *  return 1 if the point is the neutral element and 0 otherwise
  }
  EC_POINT_is_at_infinity: function(group: PEC_GROUP; p: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_POINT_is_at_infinity;
  {* Checks whether the point is on the curve
  *  param  group  underlying EC_GROUP object
  *  param  point  EC_POINT object to check
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if the point is on the curve, 0 if not, or -1 on error
  }
  EC_POINT_is_on_curve: function(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_is_on_curve;
  {* Compares two EC_POINTs
  *  param  group  underlying EC_GROUP object
  *  param  a      first EC_POINT object
  *  param  b      second EC_POINT object
  *  param  ctx    BN_CTX object (optional)
  *  return 1 if the points are not equal, 0 if they are, or -1 on error
  }
  EC_POINT_cmp: function(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_cmp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_make_affine(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_make_affine'; deprecated 'Since OpenSSL 3.0';
  function EC_POINTs_make_affine(group: PEC_GROUP; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINTs_make_affine'; deprecated 'Since OpenSSL 3.0';
  (** Computes r = generator * n + sum_{i=0}^{num-1} p[i] * m[i]
  *  param  group  underlying EC_GROUP object
  *  param  r      EC_POINT object for the result
  *  param  n      BIGNUM with the multiplier for the group generator (optional)
  *  param  num    number further summands
  *  param  p      array of size num of EC_POINT objects
  *  param  m      array of size num of BIGNUM objects
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  *)
  function EC_POINTs_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TOpenSSL_C_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINTs_mul'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_POINT_make_affine}
  {$EXTERNALSYM EC_POINTs_make_affine}
  {$EXTERNALSYM EC_POINTs_mul}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_make_affine(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINTs_make_affine(group: PEC_GROUP; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_POINTs_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TOpenSSL_C_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_make_affine: function(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_make_affine;
  EC_POINTs_make_affine: function(group: PEC_GROUP; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINTs_make_affine;
  (** Computes r = generator * n + sum_{i=0}^{num-1} p[i] * m[i]
  *  param  group  underlying EC_GROUP object
  *  param  r      EC_POINT object for the result
  *  param  n      BIGNUM with the multiplier for the group generator (optional)
  *  param  num    number further summands
  *  param  p      array of size num of EC_POINT objects
  *  param  m      array of size num of BIGNUM objects
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  *)
  EC_POINTs_mul: function(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TOpenSSL_C_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINTs_mul;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {* Computes r = generator * n + q * m
    *  param  group  underlying EC_GROUP object
    *  param  r      EC_POINT object for the result
    *  param  n      BIGNUM with the multiplier for the group generator (optional)
    *  param  q      EC_POINT object with the first factor of the second summand
    *  param  m      BIGNUM with the second factor of the second summand
    *  param  ctx    BN_CTX object (optional)
    *  return 1 on success and 0 if an error occurred
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_POINT_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_POINT_mul';
    {$else}
  {$EXTERNALSYM EC_POINT_mul}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_POINT_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

var
  EC_POINT_mul: function(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_mul;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {* Stores multiples of generator for faster point multiplication
      *  param  group  EC_GROUP object
      *  param  ctx    BN_CTX object (optional)
      *  return 1 on success and 0 if an error occurred
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_precompute_mult'; deprecated 'Since OpenSSL 3.0';
  {* Reports whether a precomputation has been done
  *  param  group  EC_GROUP object
  *  return 1 if a pre-computation has been done and 0 otherwise
  }
  function EC_GROUP_have_precompute_mult(group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_have_precompute_mult'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_GROUP_precompute_mult}
  {$EXTERNALSYM EC_GROUP_have_precompute_mult}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_have_precompute_mult(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;

var
  EC_GROUP_precompute_mult: function(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_precompute_mult;
  {* Reports whether a precomputation has been done
  *  param  group  EC_GROUP object
  *  return 1 if a pre-computation has been done and 0 otherwise
  }
  EC_GROUP_have_precompute_mult: function(group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_have_precompute_mult;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    { OPENSSL_NO_DEPRECATED_3_0 }
    {******************************************************************}
    {                       ASN1 stuff                                 }
    {******************************************************************}
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ECPKPARAMETERS_it: PASN1_ITEM; cdecl; external CLibCrypto name 'ECPKPARAMETERS_it';
  function ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl; external CLibCrypto name 'ECPKPARAMETERS_new';
  procedure ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl; external CLibCrypto name 'ECPKPARAMETERS_free';
  function ECPARAMETERS_it: PASN1_ITEM; cdecl; external CLibCrypto name 'ECPARAMETERS_it';
  function ECPARAMETERS_new: PECPARAMETERS; cdecl; external CLibCrypto name 'ECPARAMETERS_new';
  procedure ECPARAMETERS_free(a: PECPARAMETERS); cdecl; external CLibCrypto name 'ECPARAMETERS_free';
  
  {* EC_GROUP_get_basis_type() returns the NID of the basis type used to
  * represent the field elements
  }
  function EC_GROUP_get_basis_type(_param1: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_basis_type';
    {$else}
  {$EXTERNALSYM ECPKPARAMETERS_it}
  {$EXTERNALSYM ECPKPARAMETERS_new}
  {$EXTERNALSYM ECPKPARAMETERS_free}
  {$EXTERNALSYM ECPARAMETERS_it}
  {$EXTERNALSYM ECPARAMETERS_new}
  {$EXTERNALSYM ECPARAMETERS_free}
  {$EXTERNALSYM EC_GROUP_get_basis_type}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ECPKPARAMETERS_it: PASN1_ITEM; cdecl;
  function Load_ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl;
  procedure Load_ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl;
  function Load_ECPARAMETERS_it: PASN1_ITEM; cdecl;
  function Load_ECPARAMETERS_new: PECPARAMETERS; cdecl;
  procedure Load_ECPARAMETERS_free(a: PECPARAMETERS); cdecl;
  function Load_EC_GROUP_get_basis_type(_param1: PEC_GROUP): TOpenSSL_C_INT; cdecl;

var
  ECPKPARAMETERS_it: function: PASN1_ITEM; cdecl = Load_ECPKPARAMETERS_it;
  ECPKPARAMETERS_new: function: PECPKPARAMETERS; cdecl = Load_ECPKPARAMETERS_new;
  ECPKPARAMETERS_free: procedure(a: PECPKPARAMETERS); cdecl = Load_ECPKPARAMETERS_free;
  ECPARAMETERS_it: function: PASN1_ITEM; cdecl = Load_ECPARAMETERS_it;
  ECPARAMETERS_new: function: PECPARAMETERS; cdecl = Load_ECPARAMETERS_new;
  ECPARAMETERS_free: procedure(a: PECPARAMETERS); cdecl = Load_ECPARAMETERS_free;
  
  {* EC_GROUP_get_basis_type() returns the NID of the basis type used to
  * represent the field elements
  }
  EC_GROUP_get_basis_type: function(_param1: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_basis_type;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_EC2M}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_GROUP_get_trinomial_basis(_param1: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_trinomial_basis';
  function EC_GROUP_get_pentanomial_basis(_param1: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_GROUP_get_pentanomial_basis';
      {$else}
  {$EXTERNALSYM EC_GROUP_get_trinomial_basis}
  {$EXTERNALSYM EC_GROUP_get_pentanomial_basis}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_GROUP_get_trinomial_basis(_param1: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_EC_GROUP_get_pentanomial_basis(_param1: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

var
  EC_GROUP_get_trinomial_basis: function(_param1: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_trinomial_basis;
  EC_GROUP_get_pentanomial_basis: function(_param1: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_pentanomial_basis;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_ECPKParameters(_param1: PPEC_GROUP; in_: PPbyte; len: TOpenSSL_C_INT): PEC_GROUP; cdecl; external CLibCrypto name 'd2i_ECPKParameters';
  function i2d_ECPKParameters(_param1: PEC_GROUP; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_ECPKParameters';
    {$else}
  {$EXTERNALSYM d2i_ECPKParameters}
  {$EXTERNALSYM i2d_ECPKParameters}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_ECPKParameters(_param1: PPEC_GROUP; in_: PPbyte; len: TOpenSSL_C_INT): PEC_GROUP; cdecl;
  function Load_i2d_ECPKParameters(_param1: PEC_GROUP; out_: PPbyte): TOpenSSL_C_INT; cdecl;

var
  d2i_ECPKParameters: function(_param1: PPEC_GROUP; in_: PPbyte; len: TOpenSSL_C_INT): PEC_GROUP; cdecl = Load_d2i_ECPKParameters;
  i2d_ECPKParameters: function(_param1: PEC_GROUP; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_ECPKParameters;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {# define  d2i_ECPKParameters_bio(bp,x) ASN1_d2i_bio_of(EC_GROUP, NULL, d2i_ECPKParameters, bp, x)} {Function argument out of range at line no 910}
  {# define  i2d_ECPKParameters_bio(bp,x) ASN1_i2d_bio_of(EC_GROUP, i2d_ECPKParameters, bp, x)} {Function argument out of range at line no 912}
  {# define  d2i_ECPKParameters_fp(fp,x) (EC_GROUP *)ASN1_d2i_fp(NULL, (d2i_of_void *)d2i_ECPKParameters, (fp), (void **)(x))}
  {# define  i2d_ECPKParameters_fp(fp,x) ASN1_i2d_fp((i2d_of_void *)i2d_ECPKParameters, (fp), (void *)(x))}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ECPKParameters_print(bp: PBIO; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECPKParameters_print'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ECPKParameters_print}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ECPKParameters_print(bp: PBIO; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  ECPKParameters_print: function(bp: PBIO; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ECPKParameters_print;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$ifndef  OPENSSL_NO_STDIO}


        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ECPKParameters_print_fp(fp: PFILE; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECPKParameters_print_fp'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM ECPKParameters_print_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ECPKParameters_print_fp(fp: PFILE; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  ECPKParameters_print_fp: function(fp: PFILE; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ECPKParameters_print_fp;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}
    {$endif}

const
    { OPENSSL_NO_DEPRECATED_3_0 }
    {******************************************************************}
    {                      EC_KEY functions                            }
    {******************************************************************}
    { some values for the encoding_flag }
  EC_PKEY_NO_PARAMETERS = $001;
  EC_PKEY_NO_PUBKEY = $002;
    { some values for the flags field }
  EC_FLAG_SM2_RANGE = $0004;
  EC_FLAG_COFACTOR_ECDH = $1000;
  EC_FLAG_CHECK_NAMED_GROUP = $2000;
  EC_FLAG_CHECK_NAMED_GROUP_NIST = $4000;
  EC_FLAG_CHECK_NAMED_GROUP_MASK = EC_FLAG_CHECK_NAMED_GROUP or EC_FLAG_CHECK_NAMED_GROUP_NIST;
    { Deprecated flags -  it was using 0x01..0x02 }
  EC_FLAG_NON_FIPS_ALLOW = $0000;
  EC_FLAG_FIPS_CHECKED = $0000;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {*
      *  Creates a new EC_KEY object.
      *  param  ctx  The library context for to use for this EC_KEY. May be NULL in
      *               which case the default library context is used.
      *  return EC_KEY object or NULL if an error occurred.
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_KEY_new_ex(ctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_KEY; cdecl; external CLibCrypto name 'EC_KEY_new_ex'; deprecated 'Since OpenSSL 3.0';
  {*
  *  Creates a new EC_KEY object. Same as calling EC_KEY_new_ex with a
  *  NULL library context
  *  return EC_KEY object or NULL if an error occurred.
  }
  function EC_KEY_new: PEC_KEY; cdecl; external CLibCrypto name 'EC_KEY_new'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_get_flags(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_get_flags'; deprecated 'Since OpenSSL 3.0';
  procedure EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EC_KEY_set_flags'; deprecated 'Since OpenSSL 3.0';
  procedure EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EC_KEY_clear_flags'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_decoded_from_explicit_params(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_decoded_from_explicit_params'; deprecated 'Since OpenSSL 3.0';
  {*
  *  Creates a new EC_KEY object using a named curve as underlying
  *  EC_GROUP object.
  *  param  ctx   The library context for to use for this EC_KEY. May be NULL in
  *                which case the default library context is used.
  *  param  propq Any property query string
  *  param  nid   NID of the named curve.
  *  return EC_KEY object or NULL if an error occurred.
  }
  function EC_KEY_new_by_curve_name_ex(ctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_KEY; cdecl; external CLibCrypto name 'EC_KEY_new_by_curve_name_ex'; deprecated 'Since OpenSSL 3.0';
  {*
  *  Creates a new EC_KEY object using a named curve as underlying
  *  EC_GROUP object. Same as calling EC_KEY_new_by_curve_name_ex with a NULL
  *  library context and property query string.
  *  param  nid  NID of the named curve.
  *  return EC_KEY object or NULL if an error occurred.
  }
  function EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl; external CLibCrypto name 'EC_KEY_new_by_curve_name'; deprecated 'Since OpenSSL 3.0';
  {* Frees a EC_KEY object.
  *  param  key  EC_KEY object to be freed.
  }
  procedure EC_KEY_free(key: PEC_KEY); cdecl; external CLibCrypto name 'EC_KEY_free'; deprecated 'Since OpenSSL 3.0';
  {* Copies a EC_KEY object.
  *  param  dst  destination EC_KEY object
  *  param  src  src EC_KEY object
  *  return dst or NULL if an error occurred.
  }
  function EC_KEY_copy(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl; external CLibCrypto name 'EC_KEY_copy'; deprecated 'Since OpenSSL 3.0';
  {* Creates a new EC_KEY object and copies the content from src to it.
  *  param  src  the source EC_KEY object
  *  return newly created EC_KEY object or NULL if an error occurred.
  }
  function EC_KEY_dup(src: PEC_KEY): PEC_KEY; cdecl; external CLibCrypto name 'EC_KEY_dup'; deprecated 'Since OpenSSL 3.0';
  {* Increases the internal reference count of a EC_KEY object.
  *  param  key  EC_KEY object
  *  return 1 on success and 0 if an error occurred.
  }
  function EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_up_ref'; deprecated 'Since OpenSSL 3.0';
  {* Returns the ENGINE object of a EC_KEY object
  *  param  eckey  EC_KEY object
  *  return the ENGINE object (possibly NULL).
  }
  function EC_KEY_get0_engine(eckey: PEC_KEY): PENGINE; cdecl; external CLibCrypto name 'EC_KEY_get0_engine'; deprecated 'Since OpenSSL 3.0';
  {* Returns the EC_GROUP object of a EC_KEY object
  *  param  key  EC_KEY object
  *  return the EC_GROUP object (possibly NULL).
  }
  function EC_KEY_get0_group(key: PEC_KEY): PEC_GROUP; cdecl; external CLibCrypto name 'EC_KEY_get0_group'; deprecated 'Since OpenSSL 3.0';
  {* Sets the EC_GROUP of a EC_KEY object.
  *  param  key    EC_KEY object
  *  param  group  EC_GROUP to use in the EC_KEY object (note: the EC_KEY
  *                 object will use an own copy of the EC_GROUP).
  *  return 1 on success and 0 if an error occurred.
  }
  function EC_KEY_set_group(key: PEC_KEY; group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_set_group'; deprecated 'Since OpenSSL 3.0';
  {* Returns the private key of a EC_KEY object.
  *  param  key  EC_KEY object
  *  return a BIGNUM with the private key (possibly NULL).
  }
  function EC_KEY_get0_private_key(key: PEC_KEY): PBIGNUM; cdecl; external CLibCrypto name 'EC_KEY_get0_private_key'; deprecated 'Since OpenSSL 3.0';
  {* Sets the private key of a EC_KEY object.
  *  param  key  EC_KEY object
  *  param  prv  BIGNUM with the private key (note: the EC_KEY object
  *               will use an own copy of the BIGNUM).
  *  return 1 on success and 0 if an error occurred.
  }
  function EC_KEY_set_private_key(key: PEC_KEY; prv: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_set_private_key'; deprecated 'Since OpenSSL 3.0';
  {* Returns the public key of a EC_KEY object.
  *  param  key  the EC_KEY object
  *  return a EC_POINT object with the public key (possibly NULL)
  }
  function EC_KEY_get0_public_key(key: PEC_KEY): PEC_POINT; cdecl; external CLibCrypto name 'EC_KEY_get0_public_key'; deprecated 'Since OpenSSL 3.0';
  {* Sets the public key of a EC_KEY object.
  *  param  key  EC_KEY object
  *  param  pub  EC_POINT object with the public key (note: the EC_KEY object
  *               will use an own copy of the EC_POINT object).
  *  return 1 on success and 0 if an error occurred.
  }
  function EC_KEY_set_public_key(key: PEC_KEY; pub: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_set_public_key'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_get_enc_flags(key: PEC_KEY): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'EC_KEY_get_enc_flags'; deprecated 'Since OpenSSL 3.0';
  procedure EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl; external CLibCrypto name 'EC_KEY_set_enc_flags'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_get_conv_form(key: PEC_KEY): Tpoint_conversion_form_t; cdecl; external CLibCrypto name 'EC_KEY_get_conv_form'; deprecated 'Since OpenSSL 3.0';
  procedure EC_KEY_set_conv_form(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl; external CLibCrypto name 'EC_KEY_set_conv_form'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_new_ex}
  {$EXTERNALSYM EC_KEY_new}
  {$EXTERNALSYM EC_KEY_get_flags}
  {$EXTERNALSYM EC_KEY_set_flags}
  {$EXTERNALSYM EC_KEY_clear_flags}
  {$EXTERNALSYM EC_KEY_decoded_from_explicit_params}
  {$EXTERNALSYM EC_KEY_new_by_curve_name_ex}
  {$EXTERNALSYM EC_KEY_new_by_curve_name}
  {$EXTERNALSYM EC_KEY_free}
  {$EXTERNALSYM EC_KEY_copy}
  {$EXTERNALSYM EC_KEY_dup}
  {$EXTERNALSYM EC_KEY_up_ref}
  {$EXTERNALSYM EC_KEY_get0_engine}
  {$EXTERNALSYM EC_KEY_get0_group}
  {$EXTERNALSYM EC_KEY_set_group}
  {$EXTERNALSYM EC_KEY_get0_private_key}
  {$EXTERNALSYM EC_KEY_set_private_key}
  {$EXTERNALSYM EC_KEY_get0_public_key}
  {$EXTERNALSYM EC_KEY_set_public_key}
  {$EXTERNALSYM EC_KEY_get_enc_flags}
  {$EXTERNALSYM EC_KEY_set_enc_flags}
  {$EXTERNALSYM EC_KEY_get_conv_form}
  {$EXTERNALSYM EC_KEY_set_conv_form}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_KEY_new_ex(ctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_KEY; cdecl;
  function Load_EC_KEY_new: PEC_KEY; cdecl;
  function Load_EC_KEY_get_flags(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  procedure Load_EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
  procedure Load_EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
  function Load_EC_KEY_decoded_from_explicit_params(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_new_by_curve_name_ex(ctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_KEY; cdecl;
  function Load_EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl;
  procedure Load_EC_KEY_free(key: PEC_KEY); cdecl;
  function Load_EC_KEY_copy(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl;
  function Load_EC_KEY_dup(src: PEC_KEY): PEC_KEY; cdecl;
  function Load_EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_get0_engine(eckey: PEC_KEY): PENGINE; cdecl;
  function Load_EC_KEY_get0_group(key: PEC_KEY): PEC_GROUP; cdecl;
  function Load_EC_KEY_set_group(key: PEC_KEY; group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_get0_private_key(key: PEC_KEY): PBIGNUM; cdecl;
  function Load_EC_KEY_set_private_key(key: PEC_KEY; prv: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_get0_public_key(key: PEC_KEY): PEC_POINT; cdecl;
  function Load_EC_KEY_set_public_key(key: PEC_KEY; pub: PEC_POINT): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_get_enc_flags(key: PEC_KEY): TOpenSSL_C_UINT; cdecl;
  procedure Load_EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl;
  function Load_EC_KEY_get_conv_form(key: PEC_KEY): Tpoint_conversion_form_t; cdecl;
  procedure Load_EC_KEY_set_conv_form(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl;

var
  EC_KEY_new_ex: function(ctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_KEY; cdecl = Load_EC_KEY_new_ex;
  {*
  *  Creates a new EC_KEY object. Same as calling EC_KEY_new_ex with a
  *  NULL library context
  *  return EC_KEY object or NULL if an error occurred.
  }
  EC_KEY_new: function: PEC_KEY; cdecl = Load_EC_KEY_new;
  EC_KEY_get_flags: function(key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_get_flags;
  EC_KEY_set_flags: procedure(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl = Load_EC_KEY_set_flags;
  EC_KEY_clear_flags: procedure(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl = Load_EC_KEY_clear_flags;
  EC_KEY_decoded_from_explicit_params: function(key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_decoded_from_explicit_params;
  {*
  *  Creates a new EC_KEY object using a named curve as underlying
  *  EC_GROUP object.
  *  param  ctx   The library context for to use for this EC_KEY. May be NULL in
  *                which case the default library context is used.
  *  param  propq Any property query string
  *  param  nid   NID of the named curve.
  *  return EC_KEY object or NULL if an error occurred.
  }
  EC_KEY_new_by_curve_name_ex: function(ctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_KEY; cdecl = Load_EC_KEY_new_by_curve_name_ex;
  {*
  *  Creates a new EC_KEY object using a named curve as underlying
  *  EC_GROUP object. Same as calling EC_KEY_new_by_curve_name_ex with a NULL
  *  library context and property query string.
  *  param  nid  NID of the named curve.
  *  return EC_KEY object or NULL if an error occurred.
  }
  EC_KEY_new_by_curve_name: function(nid: TOpenSSL_C_INT): PEC_KEY; cdecl = Load_EC_KEY_new_by_curve_name;
  {* Frees a EC_KEY object.
  *  param  key  EC_KEY object to be freed.
  }
  EC_KEY_free: procedure(key: PEC_KEY); cdecl = Load_EC_KEY_free;
  {* Copies a EC_KEY object.
  *  param  dst  destination EC_KEY object
  *  param  src  src EC_KEY object
  *  return dst or NULL if an error occurred.
  }
  EC_KEY_copy: function(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl = Load_EC_KEY_copy;
  {* Creates a new EC_KEY object and copies the content from src to it.
  *  param  src  the source EC_KEY object
  *  return newly created EC_KEY object or NULL if an error occurred.
  }
  EC_KEY_dup: function(src: PEC_KEY): PEC_KEY; cdecl = Load_EC_KEY_dup;
  {* Increases the internal reference count of a EC_KEY object.
  *  param  key  EC_KEY object
  *  return 1 on success and 0 if an error occurred.
  }
  EC_KEY_up_ref: function(key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_up_ref;
  {* Returns the ENGINE object of a EC_KEY object
  *  param  eckey  EC_KEY object
  *  return the ENGINE object (possibly NULL).
  }
  EC_KEY_get0_engine: function(eckey: PEC_KEY): PENGINE; cdecl = Load_EC_KEY_get0_engine;
  {* Returns the EC_GROUP object of a EC_KEY object
  *  param  key  EC_KEY object
  *  return the EC_GROUP object (possibly NULL).
  }
  EC_KEY_get0_group: function(key: PEC_KEY): PEC_GROUP; cdecl = Load_EC_KEY_get0_group;
  {* Sets the EC_GROUP of a EC_KEY object.
  *  param  key    EC_KEY object
  *  param  group  EC_GROUP to use in the EC_KEY object (note: the EC_KEY
  *                 object will use an own copy of the EC_GROUP).
  *  return 1 on success and 0 if an error occurred.
  }
  EC_KEY_set_group: function(key: PEC_KEY; group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_group;
  {* Returns the private key of a EC_KEY object.
  *  param  key  EC_KEY object
  *  return a BIGNUM with the private key (possibly NULL).
  }
  EC_KEY_get0_private_key: function(key: PEC_KEY): PBIGNUM; cdecl = Load_EC_KEY_get0_private_key;
  {* Sets the private key of a EC_KEY object.
  *  param  key  EC_KEY object
  *  param  prv  BIGNUM with the private key (note: the EC_KEY object
  *               will use an own copy of the BIGNUM).
  *  return 1 on success and 0 if an error occurred.
  }
  EC_KEY_set_private_key: function(key: PEC_KEY; prv: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_private_key;
  {* Returns the public key of a EC_KEY object.
  *  param  key  the EC_KEY object
  *  return a EC_POINT object with the public key (possibly NULL)
  }
  EC_KEY_get0_public_key: function(key: PEC_KEY): PEC_POINT; cdecl = Load_EC_KEY_get0_public_key;
  {* Sets the public key of a EC_KEY object.
  *  param  key  EC_KEY object
  *  param  pub  EC_POINT object with the public key (note: the EC_KEY object
  *               will use an own copy of the EC_POINT object).
  *  return 1 on success and 0 if an error occurred.
  }
  EC_KEY_set_public_key: function(key: PEC_KEY; pub: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_public_key;
  EC_KEY_get_enc_flags: function(key: PEC_KEY): TOpenSSL_C_UINT; cdecl = Load_EC_KEY_get_enc_flags;
  EC_KEY_set_enc_flags: procedure(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl = Load_EC_KEY_set_enc_flags;
  EC_KEY_get_conv_form: function(key: PEC_KEY): Tpoint_conversion_form_t; cdecl = Load_EC_KEY_get_conv_form;
  EC_KEY_set_conv_form: procedure(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl = Load_EC_KEY_set_conv_form;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
{# define  EC_KEY_get_ex_new_index(l,p,newf,dupf,freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef)} {Macro Return Type unknown at line no 1074}
    {OPENSSL_NO_DEPRECATED_3_0 }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_set_ex_data'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_get_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'EC_KEY_get_ex_data'; deprecated 'Since OpenSSL 3.0';
  { wrapper functions for the underlying EC_GROUP object }
  procedure EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EC_KEY_set_asn1_flag'; deprecated 'Since OpenSSL 3.0';
  {* Creates a table of pre-computed multiples of the generator to
  *  accelerate further EC_KEY operations.
  *  param  key  EC_KEY object
  *  param  ctx  BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred.
  }
  function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_precompute_mult'; deprecated 'Since OpenSSL 3.0';
  {* Creates a new ec private (and optional a new public) key.
  *  param  key  EC_KEY object
  *  return 1 on success and 0 if an error occurred.
  }
  function EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_generate_key'; deprecated 'Since OpenSSL 3.0';
  {* Verifies that a private and/or public key is valid.
  *  param  key  the EC_KEY object
  *  return 1 on success and 0 otherwise.
  }
  function EC_KEY_check_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_check_key'; deprecated 'Since OpenSSL 3.0';
  {* Indicates if an EC_KEY can be used for signing.
  *  param  eckey  the EC_KEY object
  *  return 1 if can can sign and 0 otherwise.
  }
  function EC_KEY_can_sign(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_can_sign'; deprecated 'Since OpenSSL 3.0';
  {* Sets a public key from affine coordinates performing
  *  necessary NIST PKV tests.
  *  param  key  the EC_KEY object
  *  param  x    public key x coordinate
  *  param  y    public key y coordinate
  *  return 1 on success and 0 otherwise.
  }
  function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_set_public_key_affine_coordinates'; deprecated 'Since OpenSSL 3.0';
  {* Encodes an EC_KEY public key to an allocated octet string
  *  param  key    key to encode
  *  param  form   point conversion form
  *  param  pbuf   returns pointer to allocated buffer
  *  param  ctx    BN_CTX object (optional)
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  function EC_KEY_key2buf(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_KEY_key2buf'; deprecated 'Since OpenSSL 3.0';
  {* Decodes a EC_KEY public key from a octet string
  *  param  key    key to decode
  *  param  buf    memory buffer with the encoded ec point
  *  param  len    length of the encoded ec point
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  function EC_KEY_oct2key(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_oct2key'; deprecated 'Since OpenSSL 3.0';
  {* Decodes an EC_KEY private key from an octet string
  *  param  key    key to decode
  *  param  buf    memory buffer with the encoded private key
  *  param  len    length of the encoded key
  *  return 1 on success and 0 if an error occurred
  }
  function EC_KEY_oct2priv(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_oct2priv'; deprecated 'Since OpenSSL 3.0';
  {* Encodes a EC_KEY private key to an octet string
  *  param  key    key to encode
  *  param  buf    memory buffer for the result. If NULL the function returns
  *                 required buffer size.
  *  param  len    length of the memory buffer
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  function EC_KEY_priv2oct(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_KEY_priv2oct'; deprecated 'Since OpenSSL 3.0';
  {* Encodes an EC_KEY private key to an allocated octet string
  *  param  eckey  key to encode
  *  param  pbuf   returns pointer to allocated buffer
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  function EC_KEY_priv2buf(eckey: PEC_KEY; pbuf: PPbyte): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EC_KEY_priv2buf'; deprecated 'Since OpenSSL 3.0';
  {******************************************************************}
  {        de- and encoding functions for SEC1 ECPrivateKey          }
  {******************************************************************}
  {* Decodes a private key from a memory buffer.
  *  param  key  a pointer to a EC_KEY object which should be used (or NULL)
  *  param  in   pointer to memory with the DER encoded private key
  *  param  len  length of the DER encoded private key
  *  return the decoded private key or NULL if an error occurred.
  }
  function d2i_ECPrivateKey(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl; external CLibCrypto name 'd2i_ECPrivateKey'; deprecated 'Since OpenSSL 3.0';
  {* Encodes a private key object and stores the result in a buffer.
  *  param  key  the EC_KEY object to encode
  *  param  out  the buffer for the result (if NULL the function returns number
  *               of bytes needed).
  *  return 1 on success and 0 if an error occurred.
  }
  function i2d_ECPrivateKey(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_ECPrivateKey'; deprecated 'Since OpenSSL 3.0';
  {******************************************************************}
  {        de- and encoding functions for EC parameters              }
  {******************************************************************}
  {* Decodes ec parameter from a memory buffer.
  *  param  key  a pointer to a EC_KEY object which should be used (or NULL)
  *  param  in   pointer to memory with the DER encoded ec parameters
  *  param  len  length of the DER encoded ec parameters
  *  return a EC_KEY object with the decoded parameters or NULL if an error
  *          occurred.
  }
  function d2i_ECParameters(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl; external CLibCrypto name 'd2i_ECParameters'; deprecated 'Since OpenSSL 3.0';
  {* Encodes ec parameter and stores the result in a buffer.
  *  param  key  the EC_KEY object with ec parameters to encode
  *  param  out  the buffer for the result (if NULL the function returns number
  *               of bytes needed).
  *  return 1 on success and 0 if an error occurred.
  }
  function i2d_ECParameters(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_ECParameters'; deprecated 'Since OpenSSL 3.0';
  {******************************************************************}
  {         de- and encoding functions for EC public key             }
  {         (octet string, not DER -- hence 'o2i' and 'i2o')         }
  {******************************************************************}
  {* Decodes an ec public key from a octet string.
  *  param  key  a pointer to a EC_KEY object which should be used
  *  param  in   memory buffer with the encoded public key
  *  param  len  length of the encoded public key
  *  return EC_KEY object with decoded public key or NULL if an error
  *          occurred.
  }
  function o2i_ECPublicKey(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl; external CLibCrypto name 'o2i_ECPublicKey'; deprecated 'Since OpenSSL 3.0';
  {* Encodes an ec public key in an octet string.
  *  param  key  the EC_KEY object with the public key
  *  param  out  the buffer for the result (if NULL the function returns number
  *               of bytes needed).
  *  return 1 on success and 0 if an error occurred
  }
  function i2o_ECPublicKey(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2o_ECPublicKey'; deprecated 'Since OpenSSL 3.0';
  {* Prints out the ec parameters on human readable form.
  *  param  bp   BIO object to which the information is printed
  *  param  key  EC_KEY object
  *  return 1 on success and 0 if an error occurred
  }
  function ECParameters_print(bp: PBIO; key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECParameters_print'; deprecated 'Since OpenSSL 3.0';
  {* Prints out the contents of a EC_KEY object
  *  param  bp   BIO object to which the information is printed
  *  param  key  EC_KEY object
  *  param  off  line offset
  *  return 1 on success and 0 if an error occurred
  }
  function EC_KEY_print(bp: PBIO; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_print'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_set_ex_data}
  {$EXTERNALSYM EC_KEY_get_ex_data}
  {$EXTERNALSYM EC_KEY_set_asn1_flag}
  {$EXTERNALSYM EC_KEY_precompute_mult}
  {$EXTERNALSYM EC_KEY_generate_key}
  {$EXTERNALSYM EC_KEY_check_key}
  {$EXTERNALSYM EC_KEY_can_sign}
  {$EXTERNALSYM EC_KEY_set_public_key_affine_coordinates}
  {$EXTERNALSYM EC_KEY_key2buf}
  {$EXTERNALSYM EC_KEY_oct2key}
  {$EXTERNALSYM EC_KEY_oct2priv}
  {$EXTERNALSYM EC_KEY_priv2oct}
  {$EXTERNALSYM EC_KEY_priv2buf}
  {$EXTERNALSYM d2i_ECPrivateKey}
  {$EXTERNALSYM i2d_ECPrivateKey}
  {$EXTERNALSYM d2i_ECParameters}
  {$EXTERNALSYM i2d_ECParameters}
  {$EXTERNALSYM o2i_ECPublicKey}
  {$EXTERNALSYM i2o_ECPublicKey}
  {$EXTERNALSYM ECParameters_print}
  {$EXTERNALSYM EC_KEY_print}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_get_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT): pointer; cdecl;
  procedure Load_EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl;
  function Load_EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_check_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_can_sign(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_key2buf(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
  function Load_EC_KEY_oct2key(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_oct2priv(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_priv2oct(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
  function Load_EC_KEY_priv2buf(eckey: PEC_KEY; pbuf: PPbyte): TOpenSSL_C_SIZET; cdecl;
  function Load_d2i_ECPrivateKey(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl;
  function Load_i2d_ECPrivateKey(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_d2i_ECParameters(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl;
  function Load_i2d_ECParameters(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_o2i_ECPublicKey(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl;
  function Load_i2o_ECPublicKey(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_ECParameters_print(bp: PBIO; key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_print(bp: PBIO; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EC_KEY_set_ex_data: function(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_ex_data;
  EC_KEY_get_ex_data: function(key: PEC_KEY; idx: TOpenSSL_C_INT): pointer; cdecl = Load_EC_KEY_get_ex_data;
  { wrapper functions for the underlying EC_GROUP object }
  EC_KEY_set_asn1_flag: procedure(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl = Load_EC_KEY_set_asn1_flag;
  {* Creates a table of pre-computed multiples of the generator to
  *  accelerate further EC_KEY operations.
  *  param  key  EC_KEY object
  *  param  ctx  BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred.
  }
  EC_KEY_precompute_mult: function(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_KEY_precompute_mult;
  {* Creates a new ec private (and optional a new public) key.
  *  param  key  EC_KEY object
  *  return 1 on success and 0 if an error occurred.
  }
  EC_KEY_generate_key: function(key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_generate_key;
  {* Verifies that a private and/or public key is valid.
  *  param  key  the EC_KEY object
  *  return 1 on success and 0 otherwise.
  }
  EC_KEY_check_key: function(key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_check_key;
  {* Indicates if an EC_KEY can be used for signing.
  *  param  eckey  the EC_KEY object
  *  return 1 if can can sign and 0 otherwise.
  }
  EC_KEY_can_sign: function(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_can_sign;
  {* Sets a public key from affine coordinates performing
  *  necessary NIST PKV tests.
  *  param  key  the EC_KEY object
  *  param  x    public key x coordinate
  *  param  y    public key y coordinate
  *  return 1 on success and 0 otherwise.
  }
  EC_KEY_set_public_key_affine_coordinates: function(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_public_key_affine_coordinates;
  {* Encodes an EC_KEY public key to an allocated octet string
  *  param  key    key to encode
  *  param  form   point conversion form
  *  param  pbuf   returns pointer to allocated buffer
  *  param  ctx    BN_CTX object (optional)
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  EC_KEY_key2buf: function(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = Load_EC_KEY_key2buf;
  {* Decodes a EC_KEY public key from a octet string
  *  param  key    key to decode
  *  param  buf    memory buffer with the encoded ec point
  *  param  len    length of the encoded ec point
  *  param  ctx    BN_CTX object (optional)
  *  return 1 on success and 0 if an error occurred
  }
  EC_KEY_oct2key: function(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_KEY_oct2key;
  {* Decodes an EC_KEY private key from an octet string
  *  param  key    key to decode
  *  param  buf    memory buffer with the encoded private key
  *  param  len    length of the encoded key
  *  return 1 on success and 0 if an error occurred
  }
  EC_KEY_oct2priv: function(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EC_KEY_oct2priv;
  {* Encodes a EC_KEY private key to an octet string
  *  param  key    key to encode
  *  param  buf    memory buffer for the result. If NULL the function returns
  *                 required buffer size.
  *  param  len    length of the memory buffer
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  EC_KEY_priv2oct: function(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_EC_KEY_priv2oct;
  {* Encodes an EC_KEY private key to an allocated octet string
  *  param  eckey  key to encode
  *  param  pbuf   returns pointer to allocated buffer
  *  return the length of the encoded octet string or 0 if an error occurred
  }
  EC_KEY_priv2buf: function(eckey: PEC_KEY; pbuf: PPbyte): TOpenSSL_C_SIZET; cdecl = Load_EC_KEY_priv2buf;
  {******************************************************************}
  {        de- and encoding functions for SEC1 ECPrivateKey          }
  {******************************************************************}
  {* Decodes a private key from a memory buffer.
  *  param  key  a pointer to a EC_KEY object which should be used (or NULL)
  *  param  in   pointer to memory with the DER encoded private key
  *  param  len  length of the DER encoded private key
  *  return the decoded private key or NULL if an error occurred.
  }
  d2i_ECPrivateKey: function(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl = Load_d2i_ECPrivateKey;
  {* Encodes a private key object and stores the result in a buffer.
  *  param  key  the EC_KEY object to encode
  *  param  out  the buffer for the result (if NULL the function returns number
  *               of bytes needed).
  *  return 1 on success and 0 if an error occurred.
  }
  i2d_ECPrivateKey: function(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_ECPrivateKey;
  {******************************************************************}
  {        de- and encoding functions for EC parameters              }
  {******************************************************************}
  {* Decodes ec parameter from a memory buffer.
  *  param  key  a pointer to a EC_KEY object which should be used (or NULL)
  *  param  in   pointer to memory with the DER encoded ec parameters
  *  param  len  length of the DER encoded ec parameters
  *  return a EC_KEY object with the decoded parameters or NULL if an error
  *          occurred.
  }
  d2i_ECParameters: function(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl = Load_d2i_ECParameters;
  {* Encodes ec parameter and stores the result in a buffer.
  *  param  key  the EC_KEY object with ec parameters to encode
  *  param  out  the buffer for the result (if NULL the function returns number
  *               of bytes needed).
  *  return 1 on success and 0 if an error occurred.
  }
  i2d_ECParameters: function(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_ECParameters;
  {******************************************************************}
  {         de- and encoding functions for EC public key             }
  {         (octet string, not DER -- hence 'o2i' and 'i2o')         }
  {******************************************************************}
  {* Decodes an ec public key from a octet string.
  *  param  key  a pointer to a EC_KEY object which should be used
  *  param  in   memory buffer with the encoded public key
  *  param  len  length of the encoded public key
  *  return EC_KEY object with decoded public key or NULL if an error
  *          occurred.
  }
  o2i_ECPublicKey: function(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl = Load_o2i_ECPublicKey;
  {* Encodes an ec public key in an octet string.
  *  param  key  the EC_KEY object with the public key
  *  param  out  the buffer for the result (if NULL the function returns number
  *               of bytes needed).
  *  return 1 on success and 0 if an error occurred
  }
  i2o_ECPublicKey: function(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2o_ECPublicKey;
  {* Prints out the ec parameters on human readable form.
  *  param  bp   BIO object to which the information is printed
  *  param  key  EC_KEY object
  *  return 1 on success and 0 if an error occurred
  }
  ECParameters_print: function(bp: PBIO; key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECParameters_print;
  {* Prints out the contents of a EC_KEY object
  *  param  bp   BIO object to which the information is printed
  *  param  key  EC_KEY object
  *  param  off  line offset
  *  return 1 on success and 0 if an error occurred
  }
  EC_KEY_print: function(bp: PBIO; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EC_KEY_print;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$ifndef  OPENSSL_NO_STDIO}


        {* Prints out the ec parameters on human readable form.
        *  param  fp   file descriptor to which the information is printed
        *  param  key  EC_KEY object
        *  return 1 on success and 0 if an error occurred
        }
        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ECParameters_print_fp(fp: PFILE; key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECParameters_print_fp'; deprecated 'Since OpenSSL 3.0';
  {* Prints out the contents of a EC_KEY object
  *  param  fp   file descriptor to which the information is printed
  *  param  key  EC_KEY object
  *  param  off  line offset
  *  return 1 on success and 0 if an error occurred
  }
  function EC_KEY_print_fp(fp: PFILE; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_print_fp'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM ECParameters_print_fp}
  {$EXTERNALSYM EC_KEY_print_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ECParameters_print_fp(fp: PFILE; key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_print_fp(fp: PFILE; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  ECParameters_print_fp: function(fp: PFILE; key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECParameters_print_fp;
  {* Prints out the contents of a EC_KEY object
  *  param  fp   file descriptor to which the information is printed
  *  param  key  EC_KEY object
  *  param  off  line offset
  *  return 1 on success and 0 if an error occurred
  }
  EC_KEY_print_fp: function(fp: PFILE; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EC_KEY_print_fp;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}


      { OPENSSL_NO_STDIO }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl; external CLibCrypto name 'EC_KEY_OpenSSL'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl; external CLibCrypto name 'EC_KEY_get_default_method'; deprecated 'Since OpenSSL 3.0';
  procedure EC_KEY_set_default_method(meth: PEC_KEY_METHOD); cdecl; external CLibCrypto name 'EC_KEY_set_default_method'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_get_method(key: PEC_KEY): PEC_KEY_METHOD; cdecl; external CLibCrypto name 'EC_KEY_get_method'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_set_method(key: PEC_KEY; meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EC_KEY_set_method'; deprecated 'Since OpenSSL 3.0';
  function EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl; external CLibCrypto name 'EC_KEY_new_method'; deprecated 'Since OpenSSL 3.0';
  {* The old name for ecdh_KDF_X9_63
  *  The ECDH KDF specification has been mistakenly attributed to ANSI X9.62,
  *  it is actually specified in ANSI X9.63.
  *  This identifier is retained for backwards compatibility
  }
  function ECDH_KDF_X9_62(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; sinfo: Pbyte; sinfolen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDH_KDF_X9_62'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_OpenSSL}
  {$EXTERNALSYM EC_KEY_get_default_method}
  {$EXTERNALSYM EC_KEY_set_default_method}
  {$EXTERNALSYM EC_KEY_get_method}
  {$EXTERNALSYM EC_KEY_set_method}
  {$EXTERNALSYM EC_KEY_new_method}
  {$EXTERNALSYM ECDH_KDF_X9_62}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl;
  function Load_EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl;
  procedure Load_EC_KEY_set_default_method(meth: PEC_KEY_METHOD); cdecl;
  function Load_EC_KEY_get_method(key: PEC_KEY): PEC_KEY_METHOD; cdecl;
  function Load_EC_KEY_set_method(key: PEC_KEY; meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl;
  function Load_ECDH_KDF_X9_62(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; sinfo: Pbyte; sinfolen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl;

var
  EC_KEY_OpenSSL: function: PEC_KEY_METHOD; cdecl = Load_EC_KEY_OpenSSL;
  EC_KEY_get_default_method: function: PEC_KEY_METHOD; cdecl = Load_EC_KEY_get_default_method;
  EC_KEY_set_default_method: procedure(meth: PEC_KEY_METHOD); cdecl = Load_EC_KEY_set_default_method;
  EC_KEY_get_method: function(key: PEC_KEY): PEC_KEY_METHOD; cdecl = Load_EC_KEY_get_method;
  EC_KEY_set_method: function(key: PEC_KEY; meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_method;
  EC_KEY_new_method: function(engine: PENGINE): PEC_KEY; cdecl = Load_EC_KEY_new_method;
  {* The old name for ecdh_KDF_X9_63
  *  The ECDH KDF specification has been mistakenly attributed to ANSI X9.62,
  *  it is actually specified in ANSI X9.63.
  *  This identifier is retained for backwards compatibility
  }
  ECDH_KDF_X9_62: function(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; sinfo: Pbyte; sinfolen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_ECDH_KDF_X9_62;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = function(in_: pointer; inlen: TOpenSSL_C_SIZET; out_: pointer; outlen: POpenSSL_C_SIZET): pointer; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ECDH_compute_key(out_: pointer; outlen: TOpenSSL_C_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TFuncType000): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDH_compute_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ECDH_compute_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ECDH_compute_key(out_: pointer; outlen: TOpenSSL_C_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TFuncType000): TOpenSSL_C_INT; cdecl;

var
  ECDH_compute_key: function(out_: pointer; outlen: TOpenSSL_C_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TFuncType000): TOpenSSL_C_INT; cdecl = Load_ECDH_compute_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}

type
  {Auto-generated forward references}
  PECDSA_SIG_st = ^TECDSA_SIG;
  PPECDSA_SIG_st = ^PECDSA_SIG_st;
  PECDSA_SIG = ^TECDSA_SIG;
  PPECDSA_SIG = ^PECDSA_SIG;
  {end of auto-generated forward references}

    { OPENSSL_NO_DEPRECATED_3_0 }
  TECDSA_SIG_st = record end;
  TECDSA_SIG = TECDSA_SIG_st;


    {* Allocates and initialize a ECDSA_SIG structure
    *  return pointer to a ECDSA_SIG structure or NULL if an error occurred
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ECDSA_SIG_new: PECDSA_SIG; cdecl; external CLibCrypto name 'ECDSA_SIG_new';
  {* frees a ECDSA_SIG structure
  *  param  sig  pointer to the ECDSA_SIG structure
  }
  procedure ECDSA_SIG_free(sig: PECDSA_SIG); cdecl; external CLibCrypto name 'ECDSA_SIG_free';
  {* i2d_ECDSA_SIG encodes content of ECDSA_SIG (note: this function modifies *pp
  *  (*pp += length of the DER encoded signature)).
  *  param  sig  pointer to the ECDSA_SIG object
  *  param  pp   pointer to a unsigned char pointer for the output or NULL
  *  return the length of the DER encoded ECDSA_SIG object or a negative value
  *          on error
  }
  function d2i_ECDSA_SIG(a: PPECDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PECDSA_SIG; cdecl; external CLibCrypto name 'd2i_ECDSA_SIG';
  function i2d_ECDSA_SIG(a: PECDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_ECDSA_SIG';
  {* d2i_ECDSA_SIG decodes an ECDSA signature (note: this function modifies *pp
  *  (*pp += len)).
  *  param  sig  pointer to ECDSA_SIG pointer (may be NULL)
  *  param  pp   memory buffer with the DER encoded signature
  *  param  len  length of the buffer
  *  return pointer to the decoded ECDSA_SIG structure (or NULL)
  }
  {* Accessor for r and s fields of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  *  param  pr   pointer to BIGNUM pointer for r (may be NULL)
  *  param  ps   pointer to BIGNUM pointer for s (may be NULL)
  }
  procedure ECDSA_SIG_get0(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl; external CLibCrypto name 'ECDSA_SIG_get0';
  {* Accessor for r field of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  }
  function ECDSA_SIG_get0_r(sig: PECDSA_SIG): PBIGNUM; cdecl; external CLibCrypto name 'ECDSA_SIG_get0_r';
  {* Accessor for s field of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  }
  function ECDSA_SIG_get0_s(sig: PECDSA_SIG): PBIGNUM; cdecl; external CLibCrypto name 'ECDSA_SIG_get0_s';
  {* Setter for r and s fields of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  *  param  r    pointer to BIGNUM for r
  *  param  s    pointer to BIGNUM for s
  }
  function ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDSA_SIG_set0';
    {$else}
  {$EXTERNALSYM ECDSA_SIG_new}
  {$EXTERNALSYM ECDSA_SIG_free}
  {$EXTERNALSYM d2i_ECDSA_SIG}
  {$EXTERNALSYM i2d_ECDSA_SIG}
  {$EXTERNALSYM ECDSA_SIG_get0}
  {$EXTERNALSYM ECDSA_SIG_get0_r}
  {$EXTERNALSYM ECDSA_SIG_get0_s}
  {$EXTERNALSYM ECDSA_SIG_set0}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ECDSA_SIG_new: PECDSA_SIG; cdecl;
  procedure Load_ECDSA_SIG_free(sig: PECDSA_SIG); cdecl;
  function Load_d2i_ECDSA_SIG(a: PPECDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PECDSA_SIG; cdecl;
  function Load_i2d_ECDSA_SIG(a: PECDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  procedure Load_ECDSA_SIG_get0(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl;
  function Load_ECDSA_SIG_get0_r(sig: PECDSA_SIG): PBIGNUM; cdecl;
  function Load_ECDSA_SIG_get0_s(sig: PECDSA_SIG): PBIGNUM; cdecl;
  function Load_ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;

var
  ECDSA_SIG_new: function: PECDSA_SIG; cdecl = Load_ECDSA_SIG_new;
  {* frees a ECDSA_SIG structure
  *  param  sig  pointer to the ECDSA_SIG structure
  }
  ECDSA_SIG_free: procedure(sig: PECDSA_SIG); cdecl = Load_ECDSA_SIG_free;
  {* i2d_ECDSA_SIG encodes content of ECDSA_SIG (note: this function modifies *pp
  *  (*pp += length of the DER encoded signature)).
  *  param  sig  pointer to the ECDSA_SIG object
  *  param  pp   pointer to a unsigned char pointer for the output or NULL
  *  return the length of the DER encoded ECDSA_SIG object or a negative value
  *          on error
  }
  d2i_ECDSA_SIG: function(a: PPECDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PECDSA_SIG; cdecl = Load_d2i_ECDSA_SIG;
  i2d_ECDSA_SIG: function(a: PECDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_ECDSA_SIG;
  {* d2i_ECDSA_SIG decodes an ECDSA signature (note: this function modifies *pp
  *  (*pp += len)).
  *  param  sig  pointer to ECDSA_SIG pointer (may be NULL)
  *  param  pp   memory buffer with the DER encoded signature
  *  param  len  length of the buffer
  *  return pointer to the decoded ECDSA_SIG structure (or NULL)
  }
  {* Accessor for r and s fields of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  *  param  pr   pointer to BIGNUM pointer for r (may be NULL)
  *  param  ps   pointer to BIGNUM pointer for s (may be NULL)
  }
  ECDSA_SIG_get0: procedure(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl = Load_ECDSA_SIG_get0;
  {* Accessor for r field of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  }
  ECDSA_SIG_get0_r: function(sig: PECDSA_SIG): PBIGNUM; cdecl = Load_ECDSA_SIG_get0_r;
  {* Accessor for s field of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  }
  ECDSA_SIG_get0_s: function(sig: PECDSA_SIG): PBIGNUM; cdecl = Load_ECDSA_SIG_get0_s;
  {* Setter for r and s fields of ECDSA_SIG
  *  param  sig  pointer to ECDSA_SIG structure
  *  param  r    pointer to BIGNUM for r
  *  param  s    pointer to BIGNUM for s
  }
  ECDSA_SIG_set0: function(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_ECDSA_SIG_set0;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {* Computes the ECDSA signature of the given hash value using
      *  the supplied private key and returns the created signature.
      *  param  dgst      pointer to the hash value
      *  param  dgst_len  length of the hash value
      *  param  eckey     EC_KEY object containing a private EC key
      *  return pointer to a ECDSA_SIG structure or NULL if an error occurred
      }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ECDSA_do_sign(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl; external CLibCrypto name 'ECDSA_do_sign'; deprecated 'Since OpenSSL 3.0';
  {* Computes ECDSA signature of a given hash value using the supplied
  *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
  *  param  dgst     pointer to the hash value to sign
  *  param  dgstlen  length of the hash value
  *  param  kinv     BIGNUM with a pre-computed inverse k (optional)
  *  param  rp       BIGNUM with a pre-computed rp value (optional),
  *                   see ECDSA_sign_setup
  *  param  eckey    EC_KEY object containing a private EC key
  *  return pointer to a ECDSA_SIG structure or NULL if an error occurred
  }
  function ECDSA_do_sign_ex(dgst: Pbyte; dgstlen: TOpenSSL_C_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl; external CLibCrypto name 'ECDSA_do_sign_ex'; deprecated 'Since OpenSSL 3.0';
  {* Verifies that the supplied signature is a valid ECDSA
  *  signature of the supplied hash value using the supplied public key.
  *  param  dgst      pointer to the hash value
  *  param  dgst_len  length of the hash value
  *  param  sig       ECDSA_SIG structure
  *  param  eckey     EC_KEY object containing a public EC key
  *  return 1 if the signature is valid, 0 if the signature is invalid
  *          and -1 on error
  }
  function ECDSA_do_verify(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDSA_do_verify'; deprecated 'Since OpenSSL 3.0';
  {* Precompute parts of the signing operation
  *  param  eckey  EC_KEY object containing a private EC key
  *  param  ctx    BN_CTX object (optional)
  *  param  kinv   BIGNUM pointer for the inverse of k
  *  param  rp     BIGNUM pointer for x coordinate of k * generator
  *  return 1 on success and 0 otherwise
  }
  function ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDSA_sign_setup'; deprecated 'Since OpenSSL 3.0';
  {* Computes ECDSA signature of a given hash value using the supplied
  *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
  *  param  type     this parameter is ignored
  *  param  dgst     pointer to the hash value to sign
  *  param  dgstlen  length of the hash value
  *  param  sig      memory for the DER encoded created signature
  *  param  siglen   pointer to the length of the returned signature
  *  param  eckey    EC_KEY object containing a private EC key
  *  return 1 on success and 0 otherwise
  }
  function ECDSA_sign(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDSA_sign'; deprecated 'Since OpenSSL 3.0';
  {* Computes ECDSA signature of a given hash value using the supplied
  *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
  *  param  type     this parameter is ignored
  *  param  dgst     pointer to the hash value to sign
  *  param  dgstlen  length of the hash value
  *  param  sig      buffer to hold the DER encoded signature
  *  param  siglen   pointer to the length of the returned signature
  *  param  kinv     BIGNUM with a pre-computed inverse k (optional)
  *  param  rp       BIGNUM with a pre-computed rp value (optional),
  *                   see ECDSA_sign_setup
  *  param  eckey    EC_KEY object containing a private EC key
  *  return 1 on success and 0 otherwise
  }
  function ECDSA_sign_ex(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDSA_sign_ex'; deprecated 'Since OpenSSL 3.0';
  {* Verifies that the given signature is valid ECDSA signature
  *  of the supplied hash value using the specified public key.
  *  param  type     this parameter is ignored
  *  param  dgst     pointer to the hash value
  *  param  dgstlen  length of the hash value
  *  param  sig      pointer to the DER encoded signature
  *  param  siglen   length of the DER encoded signature
  *  param  eckey    EC_KEY object containing a public EC key
  *  return 1 if the signature is valid, 0 if the signature is invalid
  *          and -1 on error
  }
  function ECDSA_verify(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDSA_verify'; deprecated 'Since OpenSSL 3.0';
  {* Returns the maximum length of the DER encoded signature
  *  param  eckey  EC_KEY object
  *  return numbers of bytes required for the DER encoded signature
  }
  function ECDSA_size(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ECDSA_size'; deprecated 'Since OpenSSL 3.0';
  {******************************************************************}
  {  EC_KEY_METHOD constructors, destructors, writers and accessors  }
  {******************************************************************}
  function EC_KEY_METHOD_new(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl; external CLibCrypto name 'EC_KEY_METHOD_new'; deprecated 'Since OpenSSL 3.0';
  procedure EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl; external CLibCrypto name 'EC_KEY_METHOD_free'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ECDSA_do_sign}
  {$EXTERNALSYM ECDSA_do_sign_ex}
  {$EXTERNALSYM ECDSA_do_verify}
  {$EXTERNALSYM ECDSA_sign_setup}
  {$EXTERNALSYM ECDSA_sign}
  {$EXTERNALSYM ECDSA_sign_ex}
  {$EXTERNALSYM ECDSA_verify}
  {$EXTERNALSYM ECDSA_size}
  {$EXTERNALSYM EC_KEY_METHOD_new}
  {$EXTERNALSYM EC_KEY_METHOD_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ECDSA_do_sign(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl;
  function Load_ECDSA_do_sign_ex(dgst: Pbyte; dgstlen: TOpenSSL_C_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;
  function Load_ECDSA_do_verify(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_ECDSA_sign(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_ECDSA_sign_ex(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_ECDSA_verify(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_ECDSA_size(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  function Load_EC_KEY_METHOD_new(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl;
  procedure Load_EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl;

var
  ECDSA_do_sign: function(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl = Load_ECDSA_do_sign;
  {* Computes ECDSA signature of a given hash value using the supplied
  *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
  *  param  dgst     pointer to the hash value to sign
  *  param  dgstlen  length of the hash value
  *  param  kinv     BIGNUM with a pre-computed inverse k (optional)
  *  param  rp       BIGNUM with a pre-computed rp value (optional),
  *                   see ECDSA_sign_setup
  *  param  eckey    EC_KEY object containing a private EC key
  *  return pointer to a ECDSA_SIG structure or NULL if an error occurred
  }
  ECDSA_do_sign_ex: function(dgst: Pbyte; dgstlen: TOpenSSL_C_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl = Load_ECDSA_do_sign_ex;
  {* Verifies that the supplied signature is a valid ECDSA
  *  signature of the supplied hash value using the supplied public key.
  *  param  dgst      pointer to the hash value
  *  param  dgst_len  length of the hash value
  *  param  sig       ECDSA_SIG structure
  *  param  eckey     EC_KEY object containing a public EC key
  *  return 1 if the signature is valid, 0 if the signature is invalid
  *          and -1 on error
  }
  ECDSA_do_verify: function(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_do_verify;
  {* Precompute parts of the signing operation
  *  param  eckey  EC_KEY object containing a private EC key
  *  param  ctx    BN_CTX object (optional)
  *  param  kinv   BIGNUM pointer for the inverse of k
  *  param  rp     BIGNUM pointer for x coordinate of k * generator
  *  return 1 on success and 0 otherwise
  }
  ECDSA_sign_setup: function(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl = Load_ECDSA_sign_setup;
  {* Computes ECDSA signature of a given hash value using the supplied
  *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
  *  param  type     this parameter is ignored
  *  param  dgst     pointer to the hash value to sign
  *  param  dgstlen  length of the hash value
  *  param  sig      memory for the DER encoded created signature
  *  param  siglen   pointer to the length of the returned signature
  *  param  eckey    EC_KEY object containing a private EC key
  *  return 1 on success and 0 otherwise
  }
  ECDSA_sign: function(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_sign;
  {* Computes ECDSA signature of a given hash value using the supplied
  *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
  *  param  type     this parameter is ignored
  *  param  dgst     pointer to the hash value to sign
  *  param  dgstlen  length of the hash value
  *  param  sig      buffer to hold the DER encoded signature
  *  param  siglen   pointer to the length of the returned signature
  *  param  kinv     BIGNUM with a pre-computed inverse k (optional)
  *  param  rp       BIGNUM with a pre-computed rp value (optional),
  *                   see ECDSA_sign_setup
  *  param  eckey    EC_KEY object containing a private EC key
  *  return 1 on success and 0 otherwise
  }
  ECDSA_sign_ex: function(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_sign_ex;
  {* Verifies that the given signature is valid ECDSA signature
  *  of the supplied hash value using the specified public key.
  *  param  type     this parameter is ignored
  *  param  dgst     pointer to the hash value
  *  param  dgstlen  length of the hash value
  *  param  sig      pointer to the DER encoded signature
  *  param  siglen   length of the DER encoded signature
  *  param  eckey    EC_KEY object containing a public EC key
  *  return 1 if the signature is valid, 0 if the signature is invalid
  *          and -1 on error
  }
  ECDSA_verify: function(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_verify;
  {* Returns the maximum length of the DER encoded signature
  *  param  eckey  EC_KEY object
  *  return numbers of bytes required for the DER encoded signature
  }
  ECDSA_size: function(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_size;
  {******************************************************************}
  {  EC_KEY_METHOD constructors, destructors, writers and accessors  }
  {******************************************************************}
  EC_KEY_METHOD_new: function(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl = Load_EC_KEY_METHOD_new;
  EC_KEY_METHOD_free: procedure(meth: PEC_KEY_METHOD); cdecl = Load_EC_KEY_METHOD_free;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  PFuncType003 = ^TFuncType003;
  PPFuncType003 = ^PFuncType003;
  PFuncType004 = ^TFuncType004;
  PPFuncType004 = ^PFuncType004;
  PFuncType005 = ^TFuncType005;
  PPFuncType005 = ^PFuncType005;
  PFuncType006 = ^TFuncType006;
  PPFuncType006 = ^PFuncType006;
  {end of auto-generated forward references}

  TFuncType001 = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType002 = procedure(key: PEC_KEY); cdecl;
  TFuncType003 = function(dest: PEC_KEY; src: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType004 = function(key: PEC_KEY; grp: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  TFuncType005 = function(key: PEC_KEY; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
  TFuncType006 = function(key: PEC_KEY; pub_key: PEC_POINT): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: TFuncType001; finish: TFuncType002; copy: TFuncType003; set_group: TFuncType004; set_private: TFuncType005; set_public: TFuncType006); cdecl; external CLibCrypto name 'EC_KEY_METHOD_set_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_set_init}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: TFuncType001; finish: TFuncType002; copy: TFuncType003; set_group: TFuncType004; set_private: TFuncType005; set_public: TFuncType006); cdecl;

var
  EC_KEY_METHOD_set_init: procedure(meth: PEC_KEY_METHOD; init: TFuncType001; finish: TFuncType002; copy: TFuncType003; set_group: TFuncType004; set_private: TFuncType005; set_public: TFuncType006); cdecl = Load_EC_KEY_METHOD_set_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType007 = ^TFuncType007;
  PPFuncType007 = ^PFuncType007;
  {end of auto-generated forward references}

  TFuncType007 = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: TFuncType007); cdecl; external CLibCrypto name 'EC_KEY_METHOD_set_keygen'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_set_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: TFuncType007); cdecl;

var
  EC_KEY_METHOD_set_keygen: procedure(meth: PEC_KEY_METHOD; keygen: TFuncType007); cdecl = Load_EC_KEY_METHOD_set_keygen;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType008 = ^TFuncType008;
  PPFuncType008 = ^PFuncType008;
  {end of auto-generated forward references}

  TFuncType008 = function(psec: PPbyte; pseclen: POpenSSL_C_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: TFuncType008); cdecl; external CLibCrypto name 'EC_KEY_METHOD_set_compute_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_set_compute_key}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: TFuncType008); cdecl;

var
  EC_KEY_METHOD_set_compute_key: procedure(meth: PEC_KEY_METHOD; ckey: TFuncType008); cdecl = Load_EC_KEY_METHOD_set_compute_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType009 = ^TFuncType009;
  PPFuncType009 = ^PFuncType009;
  PFuncType010 = ^TFuncType010;
  PPFuncType010 = ^PFuncType010;
  PFuncType011 = ^TFuncType011;
  PPFuncType011 = ^PFuncType011;
  {end of auto-generated forward references}

  TFuncType009 = function(type_: TOpenSSL_C_INT; dgst: Pbyte; dlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; kinv: PBIGNUM; r: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType010 = function(eckey: PEC_KEY; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  TFuncType011 = function(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; in_kinv: PBIGNUM; in_r: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: TFuncType009; sign_setup: TFuncType010; sign_sig: TFuncType011); cdecl; external CLibCrypto name 'EC_KEY_METHOD_set_sign'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_set_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: TFuncType009; sign_setup: TFuncType010; sign_sig: TFuncType011); cdecl;

var
  EC_KEY_METHOD_set_sign: procedure(meth: PEC_KEY_METHOD; sign: TFuncType009; sign_setup: TFuncType010; sign_sig: TFuncType011); cdecl = Load_EC_KEY_METHOD_set_sign;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType012 = ^TFuncType012;
  PPFuncType012 = ^PFuncType012;
  PFuncType013 = ^TFuncType013;
  PPFuncType013 = ^PFuncType013;
  {end of auto-generated forward references}

  TFuncType012 = function(type_: TOpenSSL_C_INT; dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sigbuf: Pbyte; sig_len: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType013 = function(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: TFuncType012; verify_sig: TFuncType013); cdecl; external CLibCrypto name 'EC_KEY_METHOD_set_verify'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_set_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: TFuncType012; verify_sig: TFuncType013); cdecl;

var
  EC_KEY_METHOD_set_verify: procedure(meth: PEC_KEY_METHOD; verify: TFuncType012; verify_sig: TFuncType013); cdecl = Load_EC_KEY_METHOD_set_verify;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType014 = ^TFuncType014;
  PPFuncType014 = ^PFuncType014;
  PFuncType015 = ^TFuncType015;
  PPFuncType015 = ^PFuncType015;
  PFuncType016 = ^TFuncType016;
  PPFuncType016 = ^PFuncType016;
  PFuncType017 = ^TFuncType017;
  PPFuncType017 = ^PFuncType017;
  PFuncType018 = ^TFuncType018;
  PPFuncType018 = ^PFuncType018;
  PFuncType019 = ^TFuncType019;
  PPFuncType019 = ^PFuncType019;
  {end of auto-generated forward references}

  TFuncType014 = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType015 = procedure(key: PEC_KEY); cdecl;
  TFuncType016 = function(dest: PEC_KEY; src: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType017 = function(key: PEC_KEY; grp: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  TFuncType018 = function(key: PEC_KEY; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
  TFuncType019 = function(key: PEC_KEY; pub_key: PEC_POINT): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_get_init(meth: PEC_KEY_METHOD; pinit: TFuncType014; pfinish: TFuncType015; pcopy: TFuncType016; pset_group: TFuncType017; pset_private: TFuncType018; pset_public: TFuncType019); cdecl; external CLibCrypto name 'EC_KEY_METHOD_get_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_get_init}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_get_init(meth: PEC_KEY_METHOD; pinit: TFuncType014; pfinish: TFuncType015; pcopy: TFuncType016; pset_group: TFuncType017; pset_private: TFuncType018; pset_public: TFuncType019); cdecl;

var
  EC_KEY_METHOD_get_init: procedure(meth: PEC_KEY_METHOD; pinit: TFuncType014; pfinish: TFuncType015; pcopy: TFuncType016; pset_group: TFuncType017; pset_private: TFuncType018; pset_public: TFuncType019); cdecl = Load_EC_KEY_METHOD_get_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType020 = ^TFuncType020;
  PPFuncType020 = ^PFuncType020;
  {end of auto-generated forward references}

  TFuncType020 = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_get_keygen(meth: PEC_KEY_METHOD; pkeygen: TFuncType020); cdecl; external CLibCrypto name 'EC_KEY_METHOD_get_keygen'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_get_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_get_keygen(meth: PEC_KEY_METHOD; pkeygen: TFuncType020); cdecl;

var
  EC_KEY_METHOD_get_keygen: procedure(meth: PEC_KEY_METHOD; pkeygen: TFuncType020); cdecl = Load_EC_KEY_METHOD_get_keygen;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType021 = ^TFuncType021;
  PPFuncType021 = ^PFuncType021;
  {end of auto-generated forward references}

  TFuncType021 = function(psec: PPbyte; pseclen: POpenSSL_C_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_get_compute_key(meth: PEC_KEY_METHOD; pck: TFuncType021); cdecl; external CLibCrypto name 'EC_KEY_METHOD_get_compute_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_get_compute_key}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_get_compute_key(meth: PEC_KEY_METHOD; pck: TFuncType021); cdecl;

var
  EC_KEY_METHOD_get_compute_key: procedure(meth: PEC_KEY_METHOD; pck: TFuncType021); cdecl = Load_EC_KEY_METHOD_get_compute_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType022 = ^TFuncType022;
  PPFuncType022 = ^PFuncType022;
  PFuncType023 = ^TFuncType023;
  PPFuncType023 = ^PFuncType023;
  PFuncType024 = ^TFuncType024;
  PPFuncType024 = ^PFuncType024;
  {end of auto-generated forward references}

  TFuncType022 = function(type_: TOpenSSL_C_INT; dgst: Pbyte; dlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; kinv: PBIGNUM; r: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType023 = function(eckey: PEC_KEY; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  TFuncType024 = function(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; in_kinv: PBIGNUM; in_r: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_get_sign(meth: PEC_KEY_METHOD; psign: TFuncType022; psign_setup: TFuncType023; psign_sig: TFuncType024); cdecl; external CLibCrypto name 'EC_KEY_METHOD_get_sign'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_get_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_get_sign(meth: PEC_KEY_METHOD; psign: TFuncType022; psign_setup: TFuncType023; psign_sig: TFuncType024); cdecl;

var
  EC_KEY_METHOD_get_sign: procedure(meth: PEC_KEY_METHOD; psign: TFuncType022; psign_setup: TFuncType023; psign_sig: TFuncType024); cdecl = Load_EC_KEY_METHOD_get_sign;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType025 = ^TFuncType025;
  PPFuncType025 = ^PFuncType025;
  PFuncType026 = ^TFuncType026;
  PPFuncType026 = ^PFuncType026;
  {end of auto-generated forward references}

  TFuncType025 = function(type_: TOpenSSL_C_INT; dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sigbuf: Pbyte; sig_len: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  TFuncType026 = function(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EC_KEY_METHOD_get_verify(meth: PEC_KEY_METHOD; pverify: TFuncType025; pverify_sig: TFuncType026); cdecl; external CLibCrypto name 'EC_KEY_METHOD_get_verify'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EC_KEY_METHOD_get_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EC_KEY_METHOD_get_verify(meth: PEC_KEY_METHOD; pverify: TFuncType025; pverify_sig: TFuncType026); cdecl;

var
  EC_KEY_METHOD_get_verify: procedure(meth: PEC_KEY_METHOD; pverify: TFuncType025; pverify_sig: TFuncType026); cdecl = Load_EC_KEY_METHOD_get_verify;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
{# define  EVP_EC_gen(curve) EVP_PKEY_Q_keygen(NULL, NULL, "EC", (char *)(strstr(curve, "")))} {Macro Return Type unknown at line no 1535}
{# define  ECParameters_dup(x) ASN1_dup_of(EC_KEY, i2d_ECParameters, d2i_ECParameters, x)} {Function argument out of range at line no 1538}
    { OPENSSL_NO_DEPRECATED_3_0 }
    { strstr is used to enable type checking for the variadic string arg }
    {$ifndef  __cplusplus}
      {$if  defined(__SUNPRO_C)}
        {$if  __SUNPRO_C >= 0x520}
        {$endif}
      {$endif}
    {$endif}
  {$endif}
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
function Load_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid := LoadLibCryptoFunction('EVP_PKEY_CTX_set_ec_paramgen_curve_nid');
  if not assigned(EVP_PKEY_CTX_set_ec_paramgen_curve_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_ec_paramgen_curve_nid');
  Result := EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
end;

function Load_EVP_PKEY_CTX_set_ec_param_enc(ctx: PEVP_PKEY_CTX; param_enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_ec_param_enc := LoadLibCryptoFunction('EVP_PKEY_CTX_set_ec_param_enc');
  if not assigned(EVP_PKEY_CTX_set_ec_param_enc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_ec_param_enc');
  Result := EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
end;

function Load_EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX; cofactor_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_ecdh_cofactor_mode := LoadLibCryptoFunction('EVP_PKEY_CTX_set_ecdh_cofactor_mode');
  if not assigned(EVP_PKEY_CTX_set_ecdh_cofactor_mode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_ecdh_cofactor_mode');
  Result := EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, cofactor_mode);
end;

function Load_EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_ecdh_cofactor_mode := LoadLibCryptoFunction('EVP_PKEY_CTX_get_ecdh_cofactor_mode');
  if not assigned(EVP_PKEY_CTX_get_ecdh_cofactor_mode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_ecdh_cofactor_mode');
  Result := EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx);
end;

function Load_EVP_PKEY_CTX_set_ecdh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_ecdh_kdf_type := LoadLibCryptoFunction('EVP_PKEY_CTX_set_ecdh_kdf_type');
  if not assigned(EVP_PKEY_CTX_set_ecdh_kdf_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_ecdh_kdf_type');
  Result := EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, kdf);
end;

function Load_EVP_PKEY_CTX_get_ecdh_kdf_type(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_ecdh_kdf_type := LoadLibCryptoFunction('EVP_PKEY_CTX_get_ecdh_kdf_type');
  if not assigned(EVP_PKEY_CTX_get_ecdh_kdf_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_ecdh_kdf_type');
  Result := EVP_PKEY_CTX_get_ecdh_kdf_type(ctx);
end;

function Load_EVP_PKEY_CTX_set_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_ecdh_kdf_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_ecdh_kdf_md');
  if not assigned(EVP_PKEY_CTX_set_ecdh_kdf_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_ecdh_kdf_md');
  Result := EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_get_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_ecdh_kdf_md := LoadLibCryptoFunction('EVP_PKEY_CTX_get_ecdh_kdf_md');
  if not assigned(EVP_PKEY_CTX_get_ecdh_kdf_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_ecdh_kdf_md');
  Result := EVP_PKEY_CTX_get_ecdh_kdf_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_ecdh_kdf_outlen := LoadLibCryptoFunction('EVP_PKEY_CTX_set_ecdh_kdf_outlen');
  if not assigned(EVP_PKEY_CTX_set_ecdh_kdf_outlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_ecdh_kdf_outlen');
  Result := EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, len);
end;

function Load_EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_ecdh_kdf_outlen := LoadLibCryptoFunction('EVP_PKEY_CTX_get_ecdh_kdf_outlen');
  if not assigned(EVP_PKEY_CTX_get_ecdh_kdf_outlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_ecdh_kdf_outlen');
  Result := EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx, len);
end;

function Load_EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set0_ecdh_kdf_ukm := LoadLibCryptoFunction('EVP_PKEY_CTX_set0_ecdh_kdf_ukm');
  if not assigned(EVP_PKEY_CTX_set0_ecdh_kdf_ukm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set0_ecdh_kdf_ukm');
  Result := EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, ukm, len);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get0_ecdh_kdf_ukm := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_ecdh_kdf_ukm');
  if not assigned(EVP_PKEY_CTX_get0_ecdh_kdf_ukm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_ecdh_kdf_ukm');
  Result := EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx, ukm);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_OSSL_EC_curve_nid2name(nid: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OSSL_EC_curve_nid2name := LoadLibCryptoFunction('OSSL_EC_curve_nid2name');
  if not assigned(OSSL_EC_curve_nid2name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_EC_curve_nid2name');
  Result := OSSL_EC_curve_nid2name(nid);
end;

{$ifndef  OPENSSL_NO_EC}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_GFp_simple_method: PEC_METHOD; cdecl;
begin
  EC_GFp_simple_method := LoadLibCryptoFunction('EC_GFp_simple_method');
  if not assigned(EC_GFp_simple_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_simple_method');
  Result := EC_GFp_simple_method;
end;

function Load_EC_GFp_mont_method: PEC_METHOD; cdecl;
begin
  EC_GFp_mont_method := LoadLibCryptoFunction('EC_GFp_mont_method');
  if not assigned(EC_GFp_mont_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_mont_method');
  Result := EC_GFp_mont_method;
end;

function Load_EC_GFp_nist_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nist_method := LoadLibCryptoFunction('EC_GFp_nist_method');
  if not assigned(EC_GFp_nist_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nist_method');
  Result := EC_GFp_nist_method;
end;

        {$ifndef  OPENSSL_NO_EC_NISTP_64_GCC_128}
function Load_EC_GFp_nistp224_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nistp224_method := LoadLibCryptoFunction('EC_GFp_nistp224_method');
  if not assigned(EC_GFp_nistp224_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp224_method');
  Result := EC_GFp_nistp224_method;
end;

function Load_EC_GFp_nistp256_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nistp256_method := LoadLibCryptoFunction('EC_GFp_nistp256_method');
  if not assigned(EC_GFp_nistp256_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp256_method');
  Result := EC_GFp_nistp256_method;
end;

function Load_EC_GFp_nistp521_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nistp521_method := LoadLibCryptoFunction('EC_GFp_nistp521_method');
  if not assigned(EC_GFp_nistp521_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp521_method');
  Result := EC_GFp_nistp521_method;
end;

        {$endif} { OPENSSL_NO_EC_NISTP_64_GCC_128}
        {$ifndef  OPENSSL_NO_EC2M}
function Load_EC_GF2m_simple_method: PEC_METHOD; cdecl;
begin
  EC_GF2m_simple_method := LoadLibCryptoFunction('EC_GF2m_simple_method');
  if not assigned(EC_GF2m_simple_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GF2m_simple_method');
  Result := EC_GF2m_simple_method;
end;

        {$endif} { OPENSSL_NO_EC2M}
function Load_EC_GROUP_new(meth: PEC_METHOD): PEC_GROUP; cdecl;
begin
  EC_GROUP_new := LoadLibCryptoFunction('EC_GROUP_new');
  if not assigned(EC_GROUP_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new');
  Result := EC_GROUP_new(meth);
end;

procedure Load_EC_GROUP_clear_free(group: PEC_GROUP); cdecl;
begin
  EC_GROUP_clear_free := LoadLibCryptoFunction('EC_GROUP_clear_free');
  if not assigned(EC_GROUP_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_clear_free');
  EC_GROUP_clear_free(group);
end;

function Load_EC_GROUP_method_of(group: PEC_GROUP): PEC_METHOD; cdecl;
begin
  EC_GROUP_method_of := LoadLibCryptoFunction('EC_GROUP_method_of');
  if not assigned(EC_GROUP_method_of) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_method_of');
  Result := EC_GROUP_method_of(group);
end;

function Load_EC_METHOD_get_field_type(meth: PEC_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EC_METHOD_get_field_type := LoadLibCryptoFunction('EC_METHOD_get_field_type');
  if not assigned(EC_METHOD_get_field_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_METHOD_get_field_type');
  Result := EC_METHOD_get_field_type(meth);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load_EC_GROUP_free(group: PEC_GROUP); cdecl;
begin
  EC_GROUP_free := LoadLibCryptoFunction('EC_GROUP_free');
  if not assigned(EC_GROUP_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_free');
  EC_GROUP_free(group);
end;

function Load_EC_GROUP_copy(dst: PEC_GROUP; src: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_copy := LoadLibCryptoFunction('EC_GROUP_copy');
  if not assigned(EC_GROUP_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_copy');
  Result := EC_GROUP_copy(dst, src);
end;

function Load_EC_GROUP_dup(src: PEC_GROUP): PEC_GROUP; cdecl;
begin
  EC_GROUP_dup := LoadLibCryptoFunction('EC_GROUP_dup');
  if not assigned(EC_GROUP_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_dup');
  Result := EC_GROUP_dup(src);
end;

function Load_EC_GROUP_set_generator(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_generator := LoadLibCryptoFunction('EC_GROUP_set_generator');
  if not assigned(EC_GROUP_set_generator) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_generator');
  Result := EC_GROUP_set_generator(group, generator, order, cofactor);
end;

function Load_EC_GROUP_get0_generator(group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EC_GROUP_get0_generator := LoadLibCryptoFunction('EC_GROUP_get0_generator');
  if not assigned(EC_GROUP_get0_generator) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_generator');
  Result := EC_GROUP_get0_generator(group);
end;

function Load_EC_GROUP_get_mont_data(group: PEC_GROUP): PBN_MONT_CTX; cdecl;
begin
  EC_GROUP_get_mont_data := LoadLibCryptoFunction('EC_GROUP_get_mont_data');
  if not assigned(EC_GROUP_get_mont_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_mont_data');
  Result := EC_GROUP_get_mont_data(group);
end;

function Load_EC_GROUP_get_order(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_order := LoadLibCryptoFunction('EC_GROUP_get_order');
  if not assigned(EC_GROUP_get_order) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_order');
  Result := EC_GROUP_get_order(group, order, ctx);
end;

function Load_EC_GROUP_get0_order(group: PEC_GROUP): PBIGNUM; cdecl;
begin
  EC_GROUP_get0_order := LoadLibCryptoFunction('EC_GROUP_get0_order');
  if not assigned(EC_GROUP_get0_order) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_order');
  Result := EC_GROUP_get0_order(group);
end;

function Load_EC_GROUP_order_bits(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_order_bits := LoadLibCryptoFunction('EC_GROUP_order_bits');
  if not assigned(EC_GROUP_order_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_order_bits');
  Result := EC_GROUP_order_bits(group);
end;

function Load_EC_GROUP_get_cofactor(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_cofactor := LoadLibCryptoFunction('EC_GROUP_get_cofactor');
  if not assigned(EC_GROUP_get_cofactor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_cofactor');
  Result := EC_GROUP_get_cofactor(group, cofactor, ctx);
end;

function Load_EC_GROUP_get0_cofactor(group: PEC_GROUP): PBIGNUM; cdecl;
begin
  EC_GROUP_get0_cofactor := LoadLibCryptoFunction('EC_GROUP_get0_cofactor');
  if not assigned(EC_GROUP_get0_cofactor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_cofactor');
  Result := EC_GROUP_get0_cofactor(group);
end;

procedure Load_EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl;
begin
  EC_GROUP_set_curve_name := LoadLibCryptoFunction('EC_GROUP_set_curve_name');
  if not assigned(EC_GROUP_set_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_name');
  EC_GROUP_set_curve_name(group, nid);
end;

function Load_EC_GROUP_get_curve_name(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve_name := LoadLibCryptoFunction('EC_GROUP_get_curve_name');
  if not assigned(EC_GROUP_get_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_name');
  Result := EC_GROUP_get_curve_name(group);
end;

function Load_EC_GROUP_get0_field(group: PEC_GROUP): PBIGNUM; cdecl;
begin
  EC_GROUP_get0_field := LoadLibCryptoFunction('EC_GROUP_get0_field');
  if not assigned(EC_GROUP_get0_field) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_field');
  Result := EC_GROUP_get0_field(group);
end;

function Load_EC_GROUP_get_field_type(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_field_type := LoadLibCryptoFunction('EC_GROUP_get_field_type');
  if not assigned(EC_GROUP_get_field_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_field_type');
  Result := EC_GROUP_get_field_type(group);
end;

procedure Load_EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl;
begin
  EC_GROUP_set_asn1_flag := LoadLibCryptoFunction('EC_GROUP_set_asn1_flag');
  if not assigned(EC_GROUP_set_asn1_flag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_asn1_flag');
  EC_GROUP_set_asn1_flag(group, flag);
end;

function Load_EC_GROUP_get_asn1_flag(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_asn1_flag := LoadLibCryptoFunction('EC_GROUP_get_asn1_flag');
  if not assigned(EC_GROUP_get_asn1_flag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_asn1_flag');
  Result := EC_GROUP_get_asn1_flag(group);
end;

procedure Load_EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl;
begin
  EC_GROUP_set_point_conversion_form := LoadLibCryptoFunction('EC_GROUP_set_point_conversion_form');
  if not assigned(EC_GROUP_set_point_conversion_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_point_conversion_form');
  EC_GROUP_set_point_conversion_form(group, form);
end;

function Load_EC_GROUP_get_point_conversion_form(_param1: PEC_GROUP): Tpoint_conversion_form_t; cdecl;
begin
  EC_GROUP_get_point_conversion_form := LoadLibCryptoFunction('EC_GROUP_get_point_conversion_form');
  if not assigned(EC_GROUP_get_point_conversion_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_point_conversion_form');
  Result := EC_GROUP_get_point_conversion_form(_param1);
end;

function Load_EC_GROUP_get0_seed(x: PEC_GROUP): Pbyte; cdecl;
begin
  EC_GROUP_get0_seed := LoadLibCryptoFunction('EC_GROUP_get0_seed');
  if not assigned(EC_GROUP_get0_seed) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_seed');
  Result := EC_GROUP_get0_seed(x);
end;

function Load_EC_GROUP_get_seed_len(_param1: PEC_GROUP): TOpenSSL_C_SIZET; cdecl;
begin
  EC_GROUP_get_seed_len := LoadLibCryptoFunction('EC_GROUP_get_seed_len');
  if not assigned(EC_GROUP_get_seed_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_seed_len');
  Result := EC_GROUP_get_seed_len(_param1);
end;

function Load_EC_GROUP_set_seed(_param1: PEC_GROUP; _param2: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EC_GROUP_set_seed := LoadLibCryptoFunction('EC_GROUP_set_seed');
  if not assigned(EC_GROUP_set_seed) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_seed');
  Result := EC_GROUP_set_seed(_param1, _param2, len);
end;

function Load_EC_GROUP_set_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_curve := LoadLibCryptoFunction('EC_GROUP_set_curve');
  if not assigned(EC_GROUP_set_curve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve');
  Result := EC_GROUP_set_curve(group, p, a, b, ctx);
end;

function Load_EC_GROUP_get_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve := LoadLibCryptoFunction('EC_GROUP_get_curve');
  if not assigned(EC_GROUP_get_curve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve');
  Result := EC_GROUP_get_curve(group, p, a, b, ctx);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_GROUP_set_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_curve_GFp := LoadLibCryptoFunction('EC_GROUP_set_curve_GFp');
  if not assigned(EC_GROUP_set_curve_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_GFp');
  Result := EC_GROUP_set_curve_GFp(group, p, a, b, ctx);
end;

function Load_EC_GROUP_get_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve_GFp := LoadLibCryptoFunction('EC_GROUP_get_curve_GFp');
  if not assigned(EC_GROUP_get_curve_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_GFp');
  Result := EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
end;

        {$ifndef  OPENSSL_NO_EC2M}
function Load_EC_GROUP_set_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_set_curve_GF2m');
  if not assigned(EC_GROUP_set_curve_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_GF2m');
  Result := EC_GROUP_set_curve_GF2m(group, p, a, b, ctx);
end;

function Load_EC_GROUP_get_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_get_curve_GF2m');
  if not assigned(EC_GROUP_get_curve_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_GF2m');
  Result := EC_GROUP_get_curve_GF2m(group, p, a, b, ctx);
end;

        {$endif} { OPENSSL_NO_EC2M}
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_GROUP_get_degree(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_degree := LoadLibCryptoFunction('EC_GROUP_get_degree');
  if not assigned(EC_GROUP_get_degree) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_degree');
  Result := EC_GROUP_get_degree(group);
end;

function Load_EC_GROUP_check(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_check := LoadLibCryptoFunction('EC_GROUP_check');
  if not assigned(EC_GROUP_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_check');
  Result := EC_GROUP_check(group, ctx);
end;

function Load_EC_GROUP_check_discriminant(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_check_discriminant := LoadLibCryptoFunction('EC_GROUP_check_discriminant');
  if not assigned(EC_GROUP_check_discriminant) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_check_discriminant');
  Result := EC_GROUP_check_discriminant(group, ctx);
end;

function Load_EC_GROUP_cmp(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_cmp := LoadLibCryptoFunction('EC_GROUP_cmp');
  if not assigned(EC_GROUP_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_cmp');
  Result := EC_GROUP_cmp(a, b, ctx);
end;

function Load_EC_GROUP_new_curve_GFp(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_curve_GFp := LoadLibCryptoFunction('EC_GROUP_new_curve_GFp');
  if not assigned(EC_GROUP_new_curve_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_curve_GFp');
  Result := EC_GROUP_new_curve_GFp(p, a, b, ctx);
end;

    {$ifndef  OPENSSL_NO_EC2M}
function Load_EC_GROUP_new_curve_GF2m(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_new_curve_GF2m');
  if not assigned(EC_GROUP_new_curve_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_curve_GF2m');
  Result := EC_GROUP_new_curve_GF2m(p, a, b, ctx);
end;

    {$endif} { OPENSSL_NO_EC2M}
function Load_EC_GROUP_new_from_params(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_from_params := LoadLibCryptoFunction('EC_GROUP_new_from_params');
  if not assigned(EC_GROUP_new_from_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_from_params');
  Result := EC_GROUP_new_from_params(params, libctx, propq);
end;

function Load_EC_GROUP_new_by_curve_name_ex(libctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_by_curve_name_ex := LoadLibCryptoFunction('EC_GROUP_new_by_curve_name_ex');
  if not assigned(EC_GROUP_new_by_curve_name_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_by_curve_name_ex');
  Result := EC_GROUP_new_by_curve_name_ex(libctx, propq, nid);
end;

function Load_EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_by_curve_name := LoadLibCryptoFunction('EC_GROUP_new_by_curve_name');
  if not assigned(EC_GROUP_new_by_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_by_curve_name');
  Result := EC_GROUP_new_by_curve_name(nid);
end;

function Load_EC_GROUP_new_from_ecparameters(params: PECPARAMETERS): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_from_ecparameters := LoadLibCryptoFunction('EC_GROUP_new_from_ecparameters');
  if not assigned(EC_GROUP_new_from_ecparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_from_ecparameters');
  Result := EC_GROUP_new_from_ecparameters(params);
end;

function Load_EC_GROUP_get_ecparameters(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl;
begin
  EC_GROUP_get_ecparameters := LoadLibCryptoFunction('EC_GROUP_get_ecparameters');
  if not assigned(EC_GROUP_get_ecparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_ecparameters');
  Result := EC_GROUP_get_ecparameters(group, params);
end;

function Load_EC_GROUP_new_from_ecpkparameters(params: PECPKPARAMETERS): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_from_ecpkparameters := LoadLibCryptoFunction('EC_GROUP_new_from_ecpkparameters');
  if not assigned(EC_GROUP_new_from_ecpkparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_from_ecpkparameters');
  Result := EC_GROUP_new_from_ecpkparameters(params);
end;

function Load_EC_GROUP_get_ecpkparameters(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl;
begin
  EC_GROUP_get_ecpkparameters := LoadLibCryptoFunction('EC_GROUP_get_ecpkparameters');
  if not assigned(EC_GROUP_get_ecpkparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_ecpkparameters');
  Result := EC_GROUP_get_ecpkparameters(group, params);
end;

function Load_EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EC_get_builtin_curves := LoadLibCryptoFunction('EC_get_builtin_curves');
  if not assigned(EC_get_builtin_curves) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_get_builtin_curves');
  Result := EC_get_builtin_curves(r, nitems);
end;

function Load_EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EC_curve_nid2nist := LoadLibCryptoFunction('EC_curve_nid2nist');
  if not assigned(EC_curve_nid2nist) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_curve_nid2nist');
  Result := EC_curve_nid2nist(nid);
end;

function Load_EC_curve_nist2nid(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EC_curve_nist2nid := LoadLibCryptoFunction('EC_curve_nist2nid');
  if not assigned(EC_curve_nist2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_curve_nist2nid');
  Result := EC_curve_nist2nid(name);
end;

function Load_EC_GROUP_check_named_curve(group: PEC_GROUP; nist_only: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_check_named_curve := LoadLibCryptoFunction('EC_GROUP_check_named_curve');
  if not assigned(EC_GROUP_check_named_curve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_check_named_curve');
  Result := EC_GROUP_check_named_curve(group, nist_only, ctx);
end;

function Load_EC_POINT_new(group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EC_POINT_new := LoadLibCryptoFunction('EC_POINT_new');
  if not assigned(EC_POINT_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_new');
  Result := EC_POINT_new(group);
end;

procedure Load_EC_POINT_free(point: PEC_POINT); cdecl;
begin
  EC_POINT_free := LoadLibCryptoFunction('EC_POINT_free');
  if not assigned(EC_POINT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_free');
  EC_POINT_free(point);
end;

procedure Load_EC_POINT_clear_free(point: PEC_POINT); cdecl;
begin
  EC_POINT_clear_free := LoadLibCryptoFunction('EC_POINT_clear_free');
  if not assigned(EC_POINT_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_clear_free');
  EC_POINT_clear_free(point);
end;

function Load_EC_POINT_copy(dst: PEC_POINT; src: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_copy := LoadLibCryptoFunction('EC_POINT_copy');
  if not assigned(EC_POINT_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_copy');
  Result := EC_POINT_copy(dst, src);
end;

function Load_EC_POINT_dup(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EC_POINT_dup := LoadLibCryptoFunction('EC_POINT_dup');
  if not assigned(EC_POINT_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_dup');
  Result := EC_POINT_dup(src, group);
end;

function Load_EC_POINT_set_to_infinity(group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_to_infinity := LoadLibCryptoFunction('EC_POINT_set_to_infinity');
  if not assigned(EC_POINT_set_to_infinity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_to_infinity');
  Result := EC_POINT_set_to_infinity(group, point);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_method_of(point: PEC_POINT): PEC_METHOD; cdecl;
begin
  EC_POINT_method_of := LoadLibCryptoFunction('EC_POINT_method_of');
  if not assigned(EC_POINT_method_of) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_method_of');
  Result := EC_POINT_method_of(point);
end;

function Load_EC_POINT_set_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_Jprojective_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_Jprojective_coordinates_GFp');
  if not assigned(EC_POINT_set_Jprojective_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_Jprojective_coordinates_GFp');
  Result := EC_POINT_set_Jprojective_coordinates_GFp(group, p, x, y, z, ctx);
end;

function Load_EC_POINT_get_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_Jprojective_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_get_Jprojective_coordinates_GFp');
  if not assigned(EC_POINT_get_Jprojective_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_Jprojective_coordinates_GFp');
  Result := EC_POINT_get_Jprojective_coordinates_GFp(group, p, x, y, z, ctx);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_set_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_affine_coordinates := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates');
  if not assigned(EC_POINT_set_affine_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates');
  Result := EC_POINT_set_affine_coordinates(group, p, x, y, ctx);
end;

function Load_EC_POINT_get_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_affine_coordinates := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates');
  if not assigned(EC_POINT_get_affine_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates');
  Result := EC_POINT_get_affine_coordinates(group, p, x, y, ctx);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_set_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_affine_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates_GFp');
  if not assigned(EC_POINT_set_affine_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates_GFp');
  Result := EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
end;

function Load_EC_POINT_get_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_affine_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates_GFp');
  if not assigned(EC_POINT_get_affine_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates_GFp');
  Result := EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_set_compressed_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_compressed_coordinates := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates');
  if not assigned(EC_POINT_set_compressed_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates');
  Result := EC_POINT_set_compressed_coordinates(group, p, x, y_bit, ctx);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_set_compressed_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_compressed_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates_GFp');
  if not assigned(EC_POINT_set_compressed_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates_GFp');
  Result := EC_POINT_set_compressed_coordinates_GFp(group, p, x, y_bit, ctx);
end;

        {$ifndef  OPENSSL_NO_EC2M}
function Load_EC_POINT_set_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_affine_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates_GF2m');
  if not assigned(EC_POINT_set_affine_coordinates_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates_GF2m');
  Result := EC_POINT_set_affine_coordinates_GF2m(group, p, x, y, ctx);
end;

function Load_EC_POINT_get_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_affine_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates_GF2m');
  if not assigned(EC_POINT_get_affine_coordinates_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates_GF2m');
  Result := EC_POINT_get_affine_coordinates_GF2m(group, p, x, y, ctx);
end;

function Load_EC_POINT_set_compressed_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_compressed_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates_GF2m');
  if not assigned(EC_POINT_set_compressed_coordinates_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates_GF2m');
  Result := EC_POINT_set_compressed_coordinates_GF2m(group, p, x, y_bit, ctx);
end;

        {$endif} { OPENSSL_NO_EC2M}
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_point2oct(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EC_POINT_point2oct := LoadLibCryptoFunction('EC_POINT_point2oct');
  if not assigned(EC_POINT_point2oct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2oct');
  Result := EC_POINT_point2oct(group, p, form, buf, len, ctx);
end;

function Load_EC_POINT_oct2point(group: PEC_GROUP; p: PEC_POINT; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_oct2point := LoadLibCryptoFunction('EC_POINT_oct2point');
  if not assigned(EC_POINT_oct2point) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_oct2point');
  Result := EC_POINT_oct2point(group, p, buf, len, ctx);
end;

function Load_EC_POINT_point2buf(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EC_POINT_point2buf := LoadLibCryptoFunction('EC_POINT_point2buf');
  if not assigned(EC_POINT_point2buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2buf');
  Result := EC_POINT_point2buf(group, point, form, pbuf, ctx);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_point2bn(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBIGNUM; _param5: PBN_CTX): PBIGNUM; cdecl;
begin
  EC_POINT_point2bn := LoadLibCryptoFunction('EC_POINT_point2bn');
  if not assigned(EC_POINT_point2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2bn');
  Result := EC_POINT_point2bn(_param1, _param2, form, _param4, _param5);
end;

function Load_EC_POINT_bn2point(_param1: PEC_GROUP; _param2: PBIGNUM; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl;
begin
  EC_POINT_bn2point := LoadLibCryptoFunction('EC_POINT_bn2point');
  if not assigned(EC_POINT_bn2point) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_bn2point');
  Result := EC_POINT_bn2point(_param1, _param2, _param3, _param4);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_point2hex(_param1: PEC_GROUP; _param2: PEC_POINT; form: Tpoint_conversion_form_t; _param4: PBN_CTX): PAnsiChar; cdecl;
begin
  EC_POINT_point2hex := LoadLibCryptoFunction('EC_POINT_point2hex');
  if not assigned(EC_POINT_point2hex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2hex');
  Result := EC_POINT_point2hex(_param1, _param2, form, _param4);
end;

function Load_EC_POINT_hex2point(_param1: PEC_GROUP; _param2: PAnsiChar; _param3: PEC_POINT; _param4: PBN_CTX): PEC_POINT; cdecl;
begin
  EC_POINT_hex2point := LoadLibCryptoFunction('EC_POINT_hex2point');
  if not assigned(EC_POINT_hex2point) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_hex2point');
  Result := EC_POINT_hex2point(_param1, _param2, _param3, _param4);
end;

function Load_EC_POINT_add(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_add := LoadLibCryptoFunction('EC_POINT_add');
  if not assigned(EC_POINT_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_add');
  Result := EC_POINT_add(group, r, a, b, ctx);
end;

function Load_EC_POINT_dbl(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_dbl := LoadLibCryptoFunction('EC_POINT_dbl');
  if not assigned(EC_POINT_dbl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_dbl');
  Result := EC_POINT_dbl(group, r, a, ctx);
end;

function Load_EC_POINT_invert(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_invert := LoadLibCryptoFunction('EC_POINT_invert');
  if not assigned(EC_POINT_invert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_invert');
  Result := EC_POINT_invert(group, a, ctx);
end;

function Load_EC_POINT_is_at_infinity(group: PEC_GROUP; p: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_is_at_infinity := LoadLibCryptoFunction('EC_POINT_is_at_infinity');
  if not assigned(EC_POINT_is_at_infinity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_is_at_infinity');
  Result := EC_POINT_is_at_infinity(group, p);
end;

function Load_EC_POINT_is_on_curve(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_is_on_curve := LoadLibCryptoFunction('EC_POINT_is_on_curve');
  if not assigned(EC_POINT_is_on_curve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_is_on_curve');
  Result := EC_POINT_is_on_curve(group, point, ctx);
end;

function Load_EC_POINT_cmp(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_cmp := LoadLibCryptoFunction('EC_POINT_cmp');
  if not assigned(EC_POINT_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_cmp');
  Result := EC_POINT_cmp(group, a, b, ctx);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_make_affine(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_make_affine := LoadLibCryptoFunction('EC_POINT_make_affine');
  if not assigned(EC_POINT_make_affine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_make_affine');
  Result := EC_POINT_make_affine(group, point, ctx);
end;

function Load_EC_POINTs_make_affine(group: PEC_GROUP; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINTs_make_affine := LoadLibCryptoFunction('EC_POINTs_make_affine');
  if not assigned(EC_POINTs_make_affine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINTs_make_affine');
  Result := EC_POINTs_make_affine(group, num, points, ctx);
end;

function Load_EC_POINTs_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TOpenSSL_C_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINTs_mul := LoadLibCryptoFunction('EC_POINTs_mul');
  if not assigned(EC_POINTs_mul) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINTs_mul');
  Result := EC_POINTs_mul(group, r, n, num, p, m, ctx);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_POINT_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_mul := LoadLibCryptoFunction('EC_POINT_mul');
  if not assigned(EC_POINT_mul) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_mul');
  Result := EC_POINT_mul(group, r, n, q, m, ctx);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_precompute_mult := LoadLibCryptoFunction('EC_GROUP_precompute_mult');
  if not assigned(EC_GROUP_precompute_mult) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_precompute_mult');
  Result := EC_GROUP_precompute_mult(group, ctx);
end;

function Load_EC_GROUP_have_precompute_mult(group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_have_precompute_mult := LoadLibCryptoFunction('EC_GROUP_have_precompute_mult');
  if not assigned(EC_GROUP_have_precompute_mult) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_have_precompute_mult');
  Result := EC_GROUP_have_precompute_mult(group);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_ECPKPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  ECPKPARAMETERS_it := LoadLibCryptoFunction('ECPKPARAMETERS_it');
  if not assigned(ECPKPARAMETERS_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_it');
  Result := ECPKPARAMETERS_it;
end;

function Load_ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl;
begin
  ECPKPARAMETERS_new := LoadLibCryptoFunction('ECPKPARAMETERS_new');
  if not assigned(ECPKPARAMETERS_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_new');
  Result := ECPKPARAMETERS_new;
end;

procedure Load_ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl;
begin
  ECPKPARAMETERS_free := LoadLibCryptoFunction('ECPKPARAMETERS_free');
  if not assigned(ECPKPARAMETERS_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_free');
  ECPKPARAMETERS_free(a);
end;

function Load_ECPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  ECPARAMETERS_it := LoadLibCryptoFunction('ECPARAMETERS_it');
  if not assigned(ECPARAMETERS_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_it');
  Result := ECPARAMETERS_it;
end;

function Load_ECPARAMETERS_new: PECPARAMETERS; cdecl;
begin
  ECPARAMETERS_new := LoadLibCryptoFunction('ECPARAMETERS_new');
  if not assigned(ECPARAMETERS_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_new');
  Result := ECPARAMETERS_new;
end;

procedure Load_ECPARAMETERS_free(a: PECPARAMETERS); cdecl;
begin
  ECPARAMETERS_free := LoadLibCryptoFunction('ECPARAMETERS_free');
  if not assigned(ECPARAMETERS_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_free');
  ECPARAMETERS_free(a);
end;

function Load_EC_GROUP_get_basis_type(_param1: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_basis_type := LoadLibCryptoFunction('EC_GROUP_get_basis_type');
  if not assigned(EC_GROUP_get_basis_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_basis_type');
  Result := EC_GROUP_get_basis_type(_param1);
end;

    {$ifndef  OPENSSL_NO_EC2M}
function Load_EC_GROUP_get_trinomial_basis(_param1: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_trinomial_basis := LoadLibCryptoFunction('EC_GROUP_get_trinomial_basis');
  if not assigned(EC_GROUP_get_trinomial_basis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_trinomial_basis');
  Result := EC_GROUP_get_trinomial_basis(_param1, k);
end;

function Load_EC_GROUP_get_pentanomial_basis(_param1: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_pentanomial_basis := LoadLibCryptoFunction('EC_GROUP_get_pentanomial_basis');
  if not assigned(EC_GROUP_get_pentanomial_basis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_pentanomial_basis');
  Result := EC_GROUP_get_pentanomial_basis(_param1, k1, k2, k3);
end;

    {$endif} { OPENSSL_NO_EC2M}
function Load_d2i_ECPKParameters(_param1: PPEC_GROUP; in_: PPbyte; len: TOpenSSL_C_INT): PEC_GROUP; cdecl;
begin
  d2i_ECPKParameters := LoadLibCryptoFunction('d2i_ECPKParameters');
  if not assigned(d2i_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPKParameters');
  Result := d2i_ECPKParameters(_param1, in_, len);
end;

function Load_i2d_ECPKParameters(_param1: PEC_GROUP; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECPKParameters := LoadLibCryptoFunction('i2d_ECPKParameters');
  if not assigned(i2d_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPKParameters');
  Result := i2d_ECPKParameters(_param1, out_);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ECPKParameters_print(bp: PBIO; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ECPKParameters_print := LoadLibCryptoFunction('ECPKParameters_print');
  if not assigned(ECPKParameters_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKParameters_print');
  Result := ECPKParameters_print(bp, x, off);
end;

        {$ifndef  OPENSSL_NO_STDIO}
function Load_ECPKParameters_print_fp(fp: PFILE; x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ECPKParameters_print_fp := LoadLibCryptoFunction('ECPKParameters_print_fp');
  if not assigned(ECPKParameters_print_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKParameters_print_fp');
  Result := ECPKParameters_print_fp(fp, x, off);
end;

        {$endif} { OPENSSL_NO_STDIO}
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_KEY_new_ex(ctx: POSSL_LIB_CTX; propq: PAnsiChar): PEC_KEY; cdecl;
begin
  EC_KEY_new_ex := LoadLibCryptoFunction('EC_KEY_new_ex');
  if not assigned(EC_KEY_new_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_ex');
  Result := EC_KEY_new_ex(ctx, propq);
end;

function Load_EC_KEY_new: PEC_KEY; cdecl;
begin
  EC_KEY_new := LoadLibCryptoFunction('EC_KEY_new');
  if not assigned(EC_KEY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new');
  Result := EC_KEY_new;
end;

function Load_EC_KEY_get_flags(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_get_flags := LoadLibCryptoFunction('EC_KEY_get_flags');
  if not assigned(EC_KEY_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_flags');
  Result := EC_KEY_get_flags(key);
end;

procedure Load_EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
begin
  EC_KEY_set_flags := LoadLibCryptoFunction('EC_KEY_set_flags');
  if not assigned(EC_KEY_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_flags');
  EC_KEY_set_flags(key, flags);
end;

procedure Load_EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
begin
  EC_KEY_clear_flags := LoadLibCryptoFunction('EC_KEY_clear_flags');
  if not assigned(EC_KEY_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_clear_flags');
  EC_KEY_clear_flags(key, flags);
end;

function Load_EC_KEY_decoded_from_explicit_params(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_decoded_from_explicit_params := LoadLibCryptoFunction('EC_KEY_decoded_from_explicit_params');
  if not assigned(EC_KEY_decoded_from_explicit_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_decoded_from_explicit_params');
  Result := EC_KEY_decoded_from_explicit_params(key);
end;

function Load_EC_KEY_new_by_curve_name_ex(ctx: POSSL_LIB_CTX; propq: PAnsiChar; nid: TOpenSSL_C_INT): PEC_KEY; cdecl;
begin
  EC_KEY_new_by_curve_name_ex := LoadLibCryptoFunction('EC_KEY_new_by_curve_name_ex');
  if not assigned(EC_KEY_new_by_curve_name_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_by_curve_name_ex');
  Result := EC_KEY_new_by_curve_name_ex(ctx, propq, nid);
end;

function Load_EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl;
begin
  EC_KEY_new_by_curve_name := LoadLibCryptoFunction('EC_KEY_new_by_curve_name');
  if not assigned(EC_KEY_new_by_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_by_curve_name');
  Result := EC_KEY_new_by_curve_name(nid);
end;

procedure Load_EC_KEY_free(key: PEC_KEY); cdecl;
begin
  EC_KEY_free := LoadLibCryptoFunction('EC_KEY_free');
  if not assigned(EC_KEY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_free');
  EC_KEY_free(key);
end;

function Load_EC_KEY_copy(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl;
begin
  EC_KEY_copy := LoadLibCryptoFunction('EC_KEY_copy');
  if not assigned(EC_KEY_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_copy');
  Result := EC_KEY_copy(dst, src);
end;

function Load_EC_KEY_dup(src: PEC_KEY): PEC_KEY; cdecl;
begin
  EC_KEY_dup := LoadLibCryptoFunction('EC_KEY_dup');
  if not assigned(EC_KEY_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_dup');
  Result := EC_KEY_dup(src);
end;

function Load_EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_up_ref := LoadLibCryptoFunction('EC_KEY_up_ref');
  if not assigned(EC_KEY_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_up_ref');
  Result := EC_KEY_up_ref(key);
end;

function Load_EC_KEY_get0_engine(eckey: PEC_KEY): PENGINE; cdecl;
begin
  EC_KEY_get0_engine := LoadLibCryptoFunction('EC_KEY_get0_engine');
  if not assigned(EC_KEY_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_engine');
  Result := EC_KEY_get0_engine(eckey);
end;

function Load_EC_KEY_get0_group(key: PEC_KEY): PEC_GROUP; cdecl;
begin
  EC_KEY_get0_group := LoadLibCryptoFunction('EC_KEY_get0_group');
  if not assigned(EC_KEY_get0_group) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_group');
  Result := EC_KEY_get0_group(key);
end;

function Load_EC_KEY_set_group(key: PEC_KEY; group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_group := LoadLibCryptoFunction('EC_KEY_set_group');
  if not assigned(EC_KEY_set_group) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_group');
  Result := EC_KEY_set_group(key, group);
end;

function Load_EC_KEY_get0_private_key(key: PEC_KEY): PBIGNUM; cdecl;
begin
  EC_KEY_get0_private_key := LoadLibCryptoFunction('EC_KEY_get0_private_key');
  if not assigned(EC_KEY_get0_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_private_key');
  Result := EC_KEY_get0_private_key(key);
end;

function Load_EC_KEY_set_private_key(key: PEC_KEY; prv: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_private_key := LoadLibCryptoFunction('EC_KEY_set_private_key');
  if not assigned(EC_KEY_set_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_private_key');
  Result := EC_KEY_set_private_key(key, prv);
end;

function Load_EC_KEY_get0_public_key(key: PEC_KEY): PEC_POINT; cdecl;
begin
  EC_KEY_get0_public_key := LoadLibCryptoFunction('EC_KEY_get0_public_key');
  if not assigned(EC_KEY_get0_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_public_key');
  Result := EC_KEY_get0_public_key(key);
end;

function Load_EC_KEY_set_public_key(key: PEC_KEY; pub: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_public_key := LoadLibCryptoFunction('EC_KEY_set_public_key');
  if not assigned(EC_KEY_set_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_public_key');
  Result := EC_KEY_set_public_key(key, pub);
end;

function Load_EC_KEY_get_enc_flags(key: PEC_KEY): TOpenSSL_C_UINT; cdecl;
begin
  EC_KEY_get_enc_flags := LoadLibCryptoFunction('EC_KEY_get_enc_flags');
  if not assigned(EC_KEY_get_enc_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_enc_flags');
  Result := EC_KEY_get_enc_flags(key);
end;

procedure Load_EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl;
begin
  EC_KEY_set_enc_flags := LoadLibCryptoFunction('EC_KEY_set_enc_flags');
  if not assigned(EC_KEY_set_enc_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_enc_flags');
  EC_KEY_set_enc_flags(eckey, flags);
end;

function Load_EC_KEY_get_conv_form(key: PEC_KEY): Tpoint_conversion_form_t; cdecl;
begin
  EC_KEY_get_conv_form := LoadLibCryptoFunction('EC_KEY_get_conv_form');
  if not assigned(EC_KEY_get_conv_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_conv_form');
  Result := EC_KEY_get_conv_form(key);
end;

procedure Load_EC_KEY_set_conv_form(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl;
begin
  EC_KEY_set_conv_form := LoadLibCryptoFunction('EC_KEY_set_conv_form');
  if not assigned(EC_KEY_set_conv_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_conv_form');
  EC_KEY_set_conv_form(eckey, cform);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_ex_data := LoadLibCryptoFunction('EC_KEY_set_ex_data');
  if not assigned(EC_KEY_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_ex_data');
  Result := EC_KEY_set_ex_data(key, idx, arg);
end;

function Load_EC_KEY_get_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT): pointer; cdecl;
begin
  EC_KEY_get_ex_data := LoadLibCryptoFunction('EC_KEY_get_ex_data');
  if not assigned(EC_KEY_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_ex_data');
  Result := EC_KEY_get_ex_data(key, idx);
end;

procedure Load_EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl;
begin
  EC_KEY_set_asn1_flag := LoadLibCryptoFunction('EC_KEY_set_asn1_flag');
  if not assigned(EC_KEY_set_asn1_flag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_asn1_flag');
  EC_KEY_set_asn1_flag(eckey, asn1_flag);
end;

function Load_EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_precompute_mult := LoadLibCryptoFunction('EC_KEY_precompute_mult');
  if not assigned(EC_KEY_precompute_mult) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_precompute_mult');
  Result := EC_KEY_precompute_mult(key, ctx);
end;

function Load_EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_generate_key := LoadLibCryptoFunction('EC_KEY_generate_key');
  if not assigned(EC_KEY_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_generate_key');
  Result := EC_KEY_generate_key(key);
end;

function Load_EC_KEY_check_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_check_key := LoadLibCryptoFunction('EC_KEY_check_key');
  if not assigned(EC_KEY_check_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_check_key');
  Result := EC_KEY_check_key(key);
end;

function Load_EC_KEY_can_sign(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_can_sign := LoadLibCryptoFunction('EC_KEY_can_sign');
  if not assigned(EC_KEY_can_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_can_sign');
  Result := EC_KEY_can_sign(eckey);
end;

function Load_EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_public_key_affine_coordinates := LoadLibCryptoFunction('EC_KEY_set_public_key_affine_coordinates');
  if not assigned(EC_KEY_set_public_key_affine_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_public_key_affine_coordinates');
  Result := EC_KEY_set_public_key_affine_coordinates(key, x, y);
end;

function Load_EC_KEY_key2buf(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPbyte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EC_KEY_key2buf := LoadLibCryptoFunction('EC_KEY_key2buf');
  if not assigned(EC_KEY_key2buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_key2buf');
  Result := EC_KEY_key2buf(key, form, pbuf, ctx);
end;

function Load_EC_KEY_oct2key(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_oct2key := LoadLibCryptoFunction('EC_KEY_oct2key');
  if not assigned(EC_KEY_oct2key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_oct2key');
  Result := EC_KEY_oct2key(key, buf, len, ctx);
end;

function Load_EC_KEY_oct2priv(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_oct2priv := LoadLibCryptoFunction('EC_KEY_oct2priv');
  if not assigned(EC_KEY_oct2priv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_oct2priv');
  Result := EC_KEY_oct2priv(key, buf, len);
end;

function Load_EC_KEY_priv2oct(key: PEC_KEY; buf: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EC_KEY_priv2oct := LoadLibCryptoFunction('EC_KEY_priv2oct');
  if not assigned(EC_KEY_priv2oct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_priv2oct');
  Result := EC_KEY_priv2oct(key, buf, len);
end;

function Load_EC_KEY_priv2buf(eckey: PEC_KEY; pbuf: PPbyte): TOpenSSL_C_SIZET; cdecl;
begin
  EC_KEY_priv2buf := LoadLibCryptoFunction('EC_KEY_priv2buf');
  if not assigned(EC_KEY_priv2buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_priv2buf');
  Result := EC_KEY_priv2buf(eckey, pbuf);
end;

function Load_d2i_ECPrivateKey(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl;
begin
  d2i_ECPrivateKey := LoadLibCryptoFunction('d2i_ECPrivateKey');
  if not assigned(d2i_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPrivateKey');
  Result := d2i_ECPrivateKey(key, in_, len);
end;

function Load_i2d_ECPrivateKey(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECPrivateKey := LoadLibCryptoFunction('i2d_ECPrivateKey');
  if not assigned(i2d_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPrivateKey');
  Result := i2d_ECPrivateKey(key, out_);
end;

function Load_d2i_ECParameters(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl;
begin
  d2i_ECParameters := LoadLibCryptoFunction('d2i_ECParameters');
  if not assigned(d2i_ECParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECParameters');
  Result := d2i_ECParameters(key, in_, len);
end;

function Load_i2d_ECParameters(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECParameters := LoadLibCryptoFunction('i2d_ECParameters');
  if not assigned(i2d_ECParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECParameters');
  Result := i2d_ECParameters(key, out_);
end;

function Load_o2i_ECPublicKey(key: PPEC_KEY; in_: PPbyte; len: TOpenSSL_C_INT): PEC_KEY; cdecl;
begin
  o2i_ECPublicKey := LoadLibCryptoFunction('o2i_ECPublicKey');
  if not assigned(o2i_ECPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('o2i_ECPublicKey');
  Result := o2i_ECPublicKey(key, in_, len);
end;

function Load_i2o_ECPublicKey(key: PEC_KEY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2o_ECPublicKey := LoadLibCryptoFunction('i2o_ECPublicKey');
  if not assigned(i2o_ECPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2o_ECPublicKey');
  Result := i2o_ECPublicKey(key, out_);
end;

function Load_ECParameters_print(bp: PBIO; key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECParameters_print := LoadLibCryptoFunction('ECParameters_print');
  if not assigned(ECParameters_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECParameters_print');
  Result := ECParameters_print(bp, key);
end;

function Load_EC_KEY_print(bp: PBIO; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_print := LoadLibCryptoFunction('EC_KEY_print');
  if not assigned(EC_KEY_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_print');
  Result := EC_KEY_print(bp, key, off);
end;

        {$ifndef  OPENSSL_NO_STDIO}
function Load_ECParameters_print_fp(fp: PFILE; key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECParameters_print_fp := LoadLibCryptoFunction('ECParameters_print_fp');
  if not assigned(ECParameters_print_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECParameters_print_fp');
  Result := ECParameters_print_fp(fp, key);
end;

function Load_EC_KEY_print_fp(fp: PFILE; key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_print_fp := LoadLibCryptoFunction('EC_KEY_print_fp');
  if not assigned(EC_KEY_print_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_print_fp');
  Result := EC_KEY_print_fp(fp, key, off);
end;

        {$endif} { OPENSSL_NO_STDIO}
function Load_EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_OpenSSL := LoadLibCryptoFunction('EC_KEY_OpenSSL');
  if not assigned(EC_KEY_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_OpenSSL');
  Result := EC_KEY_OpenSSL;
end;

function Load_EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_get_default_method := LoadLibCryptoFunction('EC_KEY_get_default_method');
  if not assigned(EC_KEY_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_default_method');
  Result := EC_KEY_get_default_method;
end;

procedure Load_EC_KEY_set_default_method(meth: PEC_KEY_METHOD); cdecl;
begin
  EC_KEY_set_default_method := LoadLibCryptoFunction('EC_KEY_set_default_method');
  if not assigned(EC_KEY_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_default_method');
  EC_KEY_set_default_method(meth);
end;

function Load_EC_KEY_get_method(key: PEC_KEY): PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_get_method := LoadLibCryptoFunction('EC_KEY_get_method');
  if not assigned(EC_KEY_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_method');
  Result := EC_KEY_get_method(key);
end;

function Load_EC_KEY_set_method(key: PEC_KEY; meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_method := LoadLibCryptoFunction('EC_KEY_set_method');
  if not assigned(EC_KEY_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_method');
  Result := EC_KEY_set_method(key, meth);
end;

function Load_EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl;
begin
  EC_KEY_new_method := LoadLibCryptoFunction('EC_KEY_new_method');
  if not assigned(EC_KEY_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_method');
  Result := EC_KEY_new_method(engine);
end;

function Load_ECDH_KDF_X9_62(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; sinfo: Pbyte; sinfolen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  ECDH_KDF_X9_62 := LoadLibCryptoFunction('ECDH_KDF_X9_62');
  if not assigned(ECDH_KDF_X9_62) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDH_KDF_X9_62');
  Result := ECDH_KDF_X9_62(out_, outlen, Z, Zlen, sinfo, sinfolen, md);
end;

function Load_ECDH_compute_key(out_: pointer; outlen: TOpenSSL_C_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TFuncType000): TOpenSSL_C_INT; cdecl;
begin
  ECDH_compute_key := LoadLibCryptoFunction('ECDH_compute_key');
  if not assigned(ECDH_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDH_compute_key');
  Result := ECDH_compute_key(out_, outlen, pub_key, ecdh, KDF);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_ECDSA_SIG_new: PECDSA_SIG; cdecl;
begin
  ECDSA_SIG_new := LoadLibCryptoFunction('ECDSA_SIG_new');
  if not assigned(ECDSA_SIG_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_new');
  Result := ECDSA_SIG_new;
end;

procedure Load_ECDSA_SIG_free(sig: PECDSA_SIG); cdecl;
begin
  ECDSA_SIG_free := LoadLibCryptoFunction('ECDSA_SIG_free');
  if not assigned(ECDSA_SIG_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_free');
  ECDSA_SIG_free(sig);
end;

function Load_d2i_ECDSA_SIG(a: PPECDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PECDSA_SIG; cdecl;
begin
  d2i_ECDSA_SIG := LoadLibCryptoFunction('d2i_ECDSA_SIG');
  if not assigned(d2i_ECDSA_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECDSA_SIG');
  Result := d2i_ECDSA_SIG(a, in_, len);
end;

function Load_i2d_ECDSA_SIG(a: PECDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECDSA_SIG := LoadLibCryptoFunction('i2d_ECDSA_SIG');
  if not assigned(i2d_ECDSA_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECDSA_SIG');
  Result := i2d_ECDSA_SIG(a, out_);
end;

procedure Load_ECDSA_SIG_get0(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl;
begin
  ECDSA_SIG_get0 := LoadLibCryptoFunction('ECDSA_SIG_get0');
  if not assigned(ECDSA_SIG_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0');
  ECDSA_SIG_get0(sig, pr, ps);
end;

function Load_ECDSA_SIG_get0_r(sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  ECDSA_SIG_get0_r := LoadLibCryptoFunction('ECDSA_SIG_get0_r');
  if not assigned(ECDSA_SIG_get0_r) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0_r');
  Result := ECDSA_SIG_get0_r(sig);
end;

function Load_ECDSA_SIG_get0_s(sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  ECDSA_SIG_get0_s := LoadLibCryptoFunction('ECDSA_SIG_get0_s');
  if not assigned(ECDSA_SIG_get0_s) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0_s');
  Result := ECDSA_SIG_get0_s(sig);
end;

function Load_ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_SIG_set0 := LoadLibCryptoFunction('ECDSA_SIG_set0');
  if not assigned(ECDSA_SIG_set0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_set0');
  Result := ECDSA_SIG_set0(sig, r, s);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ECDSA_do_sign(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  ECDSA_do_sign := LoadLibCryptoFunction('ECDSA_do_sign');
  if not assigned(ECDSA_do_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_sign');
  Result := ECDSA_do_sign(dgst, dgst_len, eckey);
end;

function Load_ECDSA_do_sign_ex(dgst: Pbyte; dgstlen: TOpenSSL_C_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  ECDSA_do_sign_ex := LoadLibCryptoFunction('ECDSA_do_sign_ex');
  if not assigned(ECDSA_do_sign_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_sign_ex');
  Result := ECDSA_do_sign_ex(dgst, dgstlen, kinv, rp, eckey);
end;

function Load_ECDSA_do_verify(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_do_verify := LoadLibCryptoFunction('ECDSA_do_verify');
  if not assigned(ECDSA_do_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_verify');
  Result := ECDSA_do_verify(dgst, dgst_len, sig, eckey);
end;

function Load_ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_sign_setup := LoadLibCryptoFunction('ECDSA_sign_setup');
  if not assigned(ECDSA_sign_setup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign_setup');
  Result := ECDSA_sign_setup(eckey, ctx, kinv, rp);
end;

function Load_ECDSA_sign(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_sign := LoadLibCryptoFunction('ECDSA_sign');
  if not assigned(ECDSA_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign');
  Result := ECDSA_sign(type_, dgst, dgstlen, sig, siglen, eckey);
end;

function Load_ECDSA_sign_ex(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_sign_ex := LoadLibCryptoFunction('ECDSA_sign_ex');
  if not assigned(ECDSA_sign_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign_ex');
  Result := ECDSA_sign_ex(type_, dgst, dgstlen, sig, siglen, kinv, rp, eckey);
end;

function Load_ECDSA_verify(type_: TOpenSSL_C_INT; dgst: Pbyte; dgstlen: TOpenSSL_C_INT; sig: Pbyte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_verify := LoadLibCryptoFunction('ECDSA_verify');
  if not assigned(ECDSA_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_verify');
  Result := ECDSA_verify(type_, dgst, dgstlen, sig, siglen, eckey);
end;

function Load_ECDSA_size(eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_size := LoadLibCryptoFunction('ECDSA_size');
  if not assigned(ECDSA_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_size');
  Result := ECDSA_size(eckey);
end;

function Load_EC_KEY_METHOD_new(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_METHOD_new := LoadLibCryptoFunction('EC_KEY_METHOD_new');
  if not assigned(EC_KEY_METHOD_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_new');
  Result := EC_KEY_METHOD_new(meth);
end;

procedure Load_EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl;
begin
  EC_KEY_METHOD_free := LoadLibCryptoFunction('EC_KEY_METHOD_free');
  if not assigned(EC_KEY_METHOD_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_free');
  EC_KEY_METHOD_free(meth);
end;

procedure Load_EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: TFuncType001; finish: TFuncType002; copy: TFuncType003; set_group: TFuncType004; set_private: TFuncType005; set_public: TFuncType006); cdecl;
begin
  EC_KEY_METHOD_set_init := LoadLibCryptoFunction('EC_KEY_METHOD_set_init');
  if not assigned(EC_KEY_METHOD_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_init');
  EC_KEY_METHOD_set_init(meth, init, finish, copy, set_group, set_private, set_public);
end;

procedure Load_EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: TFuncType007); cdecl;
begin
  EC_KEY_METHOD_set_keygen := LoadLibCryptoFunction('EC_KEY_METHOD_set_keygen');
  if not assigned(EC_KEY_METHOD_set_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_keygen');
  EC_KEY_METHOD_set_keygen(meth, keygen);
end;

procedure Load_EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: TFuncType008); cdecl;
begin
  EC_KEY_METHOD_set_compute_key := LoadLibCryptoFunction('EC_KEY_METHOD_set_compute_key');
  if not assigned(EC_KEY_METHOD_set_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_compute_key');
  EC_KEY_METHOD_set_compute_key(meth, ckey);
end;

procedure Load_EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: TFuncType009; sign_setup: TFuncType010; sign_sig: TFuncType011); cdecl;
begin
  EC_KEY_METHOD_set_sign := LoadLibCryptoFunction('EC_KEY_METHOD_set_sign');
  if not assigned(EC_KEY_METHOD_set_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_sign');
  EC_KEY_METHOD_set_sign(meth, sign, sign_setup, sign_sig);
end;

procedure Load_EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: TFuncType012; verify_sig: TFuncType013); cdecl;
begin
  EC_KEY_METHOD_set_verify := LoadLibCryptoFunction('EC_KEY_METHOD_set_verify');
  if not assigned(EC_KEY_METHOD_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_verify');
  EC_KEY_METHOD_set_verify(meth, verify, verify_sig);
end;

procedure Load_EC_KEY_METHOD_get_init(meth: PEC_KEY_METHOD; pinit: TFuncType014; pfinish: TFuncType015; pcopy: TFuncType016; pset_group: TFuncType017; pset_private: TFuncType018; pset_public: TFuncType019); cdecl;
begin
  EC_KEY_METHOD_get_init := LoadLibCryptoFunction('EC_KEY_METHOD_get_init');
  if not assigned(EC_KEY_METHOD_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_init');
  EC_KEY_METHOD_get_init(meth, pinit, pfinish, pcopy, pset_group, pset_private, pset_public);
end;

procedure Load_EC_KEY_METHOD_get_keygen(meth: PEC_KEY_METHOD; pkeygen: TFuncType020); cdecl;
begin
  EC_KEY_METHOD_get_keygen := LoadLibCryptoFunction('EC_KEY_METHOD_get_keygen');
  if not assigned(EC_KEY_METHOD_get_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_keygen');
  EC_KEY_METHOD_get_keygen(meth, pkeygen);
end;

procedure Load_EC_KEY_METHOD_get_compute_key(meth: PEC_KEY_METHOD; pck: TFuncType021); cdecl;
begin
  EC_KEY_METHOD_get_compute_key := LoadLibCryptoFunction('EC_KEY_METHOD_get_compute_key');
  if not assigned(EC_KEY_METHOD_get_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_compute_key');
  EC_KEY_METHOD_get_compute_key(meth, pck);
end;

procedure Load_EC_KEY_METHOD_get_sign(meth: PEC_KEY_METHOD; psign: TFuncType022; psign_setup: TFuncType023; psign_sig: TFuncType024); cdecl;
begin
  EC_KEY_METHOD_get_sign := LoadLibCryptoFunction('EC_KEY_METHOD_get_sign');
  if not assigned(EC_KEY_METHOD_get_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_sign');
  EC_KEY_METHOD_get_sign(meth, psign, psign_setup, psign_sig);
end;

procedure Load_EC_KEY_METHOD_get_verify(meth: PEC_KEY_METHOD; pverify: TFuncType025; pverify_sig: TFuncType026); cdecl;
begin
  EC_KEY_METHOD_get_verify := LoadLibCryptoFunction('EC_KEY_METHOD_get_verify');
  if not assigned(EC_KEY_METHOD_get_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_verify');
  EC_KEY_METHOD_get_verify(meth, pverify, pverify_sig);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_EC}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid := Load_EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
  EVP_PKEY_CTX_set_ec_param_enc := Load_EVP_PKEY_CTX_set_ec_param_enc;
  EVP_PKEY_CTX_set_ecdh_cofactor_mode := Load_EVP_PKEY_CTX_set_ecdh_cofactor_mode;
  EVP_PKEY_CTX_get_ecdh_cofactor_mode := Load_EVP_PKEY_CTX_get_ecdh_cofactor_mode;
  EVP_PKEY_CTX_set_ecdh_kdf_type := Load_EVP_PKEY_CTX_set_ecdh_kdf_type;
  EVP_PKEY_CTX_get_ecdh_kdf_type := Load_EVP_PKEY_CTX_get_ecdh_kdf_type;
  EVP_PKEY_CTX_set_ecdh_kdf_md := Load_EVP_PKEY_CTX_set_ecdh_kdf_md;
  EVP_PKEY_CTX_get_ecdh_kdf_md := Load_EVP_PKEY_CTX_get_ecdh_kdf_md;
  EVP_PKEY_CTX_set_ecdh_kdf_outlen := Load_EVP_PKEY_CTX_set_ecdh_kdf_outlen;
  EVP_PKEY_CTX_get_ecdh_kdf_outlen := Load_EVP_PKEY_CTX_get_ecdh_kdf_outlen;
  EVP_PKEY_CTX_set0_ecdh_kdf_ukm := Load_EVP_PKEY_CTX_set0_ecdh_kdf_ukm;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_CTX_get0_ecdh_kdf_ukm := Load_EVP_PKEY_CTX_get0_ecdh_kdf_ukm;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  OSSL_EC_curve_nid2name := Load_OSSL_EC_curve_nid2name;
{$ifndef  OPENSSL_NO_EC}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_GFp_simple_method := Load_EC_GFp_simple_method;
  EC_GFp_mont_method := Load_EC_GFp_mont_method;
  EC_GFp_nist_method := Load_EC_GFp_nist_method;
        {$ifndef  OPENSSL_NO_EC_NISTP_64_GCC_128}
  EC_GFp_nistp224_method := Load_EC_GFp_nistp224_method;
  EC_GFp_nistp256_method := Load_EC_GFp_nistp256_method;
  EC_GFp_nistp521_method := Load_EC_GFp_nistp521_method;
        {$endif} { OPENSSL_NO_EC_NISTP_64_GCC_128}
        {$ifndef  OPENSSL_NO_EC2M}
  EC_GF2m_simple_method := Load_EC_GF2m_simple_method;
        {$endif} { OPENSSL_NO_EC2M}
  EC_GROUP_new := Load_EC_GROUP_new;
  EC_GROUP_clear_free := Load_EC_GROUP_clear_free;
  EC_GROUP_method_of := Load_EC_GROUP_method_of;
  EC_METHOD_get_field_type := Load_EC_METHOD_get_field_type;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EC_GROUP_free := Load_EC_GROUP_free;
  EC_GROUP_copy := Load_EC_GROUP_copy;
  EC_GROUP_dup := Load_EC_GROUP_dup;
  EC_GROUP_set_generator := Load_EC_GROUP_set_generator;
  EC_GROUP_get0_generator := Load_EC_GROUP_get0_generator;
  EC_GROUP_get_mont_data := Load_EC_GROUP_get_mont_data;
  EC_GROUP_get_order := Load_EC_GROUP_get_order;
  EC_GROUP_get0_order := Load_EC_GROUP_get0_order;
  EC_GROUP_order_bits := Load_EC_GROUP_order_bits;
  EC_GROUP_get_cofactor := Load_EC_GROUP_get_cofactor;
  EC_GROUP_get0_cofactor := Load_EC_GROUP_get0_cofactor;
  EC_GROUP_set_curve_name := Load_EC_GROUP_set_curve_name;
  EC_GROUP_get_curve_name := Load_EC_GROUP_get_curve_name;
  EC_GROUP_get0_field := Load_EC_GROUP_get0_field;
  EC_GROUP_get_field_type := Load_EC_GROUP_get_field_type;
  EC_GROUP_set_asn1_flag := Load_EC_GROUP_set_asn1_flag;
  EC_GROUP_get_asn1_flag := Load_EC_GROUP_get_asn1_flag;
  EC_GROUP_set_point_conversion_form := Load_EC_GROUP_set_point_conversion_form;
  EC_GROUP_get_point_conversion_form := Load_EC_GROUP_get_point_conversion_form;
  EC_GROUP_get0_seed := Load_EC_GROUP_get0_seed;
  EC_GROUP_get_seed_len := Load_EC_GROUP_get_seed_len;
  EC_GROUP_set_seed := Load_EC_GROUP_set_seed;
  EC_GROUP_set_curve := Load_EC_GROUP_set_curve;
  EC_GROUP_get_curve := Load_EC_GROUP_get_curve;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_GROUP_set_curve_GFp := Load_EC_GROUP_set_curve_GFp;
  EC_GROUP_get_curve_GFp := Load_EC_GROUP_get_curve_GFp;
        {$ifndef  OPENSSL_NO_EC2M}
  EC_GROUP_set_curve_GF2m := Load_EC_GROUP_set_curve_GF2m;
  EC_GROUP_get_curve_GF2m := Load_EC_GROUP_get_curve_GF2m;
        {$endif} { OPENSSL_NO_EC2M}
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EC_GROUP_get_degree := Load_EC_GROUP_get_degree;
  EC_GROUP_check := Load_EC_GROUP_check;
  EC_GROUP_check_discriminant := Load_EC_GROUP_check_discriminant;
  EC_GROUP_cmp := Load_EC_GROUP_cmp;
  EC_GROUP_new_curve_GFp := Load_EC_GROUP_new_curve_GFp;
    {$ifndef  OPENSSL_NO_EC2M}
  EC_GROUP_new_curve_GF2m := Load_EC_GROUP_new_curve_GF2m;
    {$endif} { OPENSSL_NO_EC2M}
  EC_GROUP_new_from_params := Load_EC_GROUP_new_from_params;
  EC_GROUP_new_by_curve_name_ex := Load_EC_GROUP_new_by_curve_name_ex;
  EC_GROUP_new_by_curve_name := Load_EC_GROUP_new_by_curve_name;
  EC_GROUP_new_from_ecparameters := Load_EC_GROUP_new_from_ecparameters;
  EC_GROUP_get_ecparameters := Load_EC_GROUP_get_ecparameters;
  EC_GROUP_new_from_ecpkparameters := Load_EC_GROUP_new_from_ecpkparameters;
  EC_GROUP_get_ecpkparameters := Load_EC_GROUP_get_ecpkparameters;
  EC_get_builtin_curves := Load_EC_get_builtin_curves;
  EC_curve_nid2nist := Load_EC_curve_nid2nist;
  EC_curve_nist2nid := Load_EC_curve_nist2nid;
  EC_GROUP_check_named_curve := Load_EC_GROUP_check_named_curve;
  EC_POINT_new := Load_EC_POINT_new;
  EC_POINT_free := Load_EC_POINT_free;
  EC_POINT_clear_free := Load_EC_POINT_clear_free;
  EC_POINT_copy := Load_EC_POINT_copy;
  EC_POINT_dup := Load_EC_POINT_dup;
  EC_POINT_set_to_infinity := Load_EC_POINT_set_to_infinity;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_method_of := Load_EC_POINT_method_of;
  EC_POINT_set_Jprojective_coordinates_GFp := Load_EC_POINT_set_Jprojective_coordinates_GFp;
  EC_POINT_get_Jprojective_coordinates_GFp := Load_EC_POINT_get_Jprojective_coordinates_GFp;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_set_affine_coordinates := Load_EC_POINT_set_affine_coordinates;
  EC_POINT_get_affine_coordinates := Load_EC_POINT_get_affine_coordinates;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_set_affine_coordinates_GFp := Load_EC_POINT_set_affine_coordinates_GFp;
  EC_POINT_get_affine_coordinates_GFp := Load_EC_POINT_get_affine_coordinates_GFp;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_set_compressed_coordinates := Load_EC_POINT_set_compressed_coordinates;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_set_compressed_coordinates_GFp := Load_EC_POINT_set_compressed_coordinates_GFp;
        {$ifndef  OPENSSL_NO_EC2M}
  EC_POINT_set_affine_coordinates_GF2m := Load_EC_POINT_set_affine_coordinates_GF2m;
  EC_POINT_get_affine_coordinates_GF2m := Load_EC_POINT_get_affine_coordinates_GF2m;
  EC_POINT_set_compressed_coordinates_GF2m := Load_EC_POINT_set_compressed_coordinates_GF2m;
        {$endif} { OPENSSL_NO_EC2M}
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_point2oct := Load_EC_POINT_point2oct;
  EC_POINT_oct2point := Load_EC_POINT_oct2point;
  EC_POINT_point2buf := Load_EC_POINT_point2buf;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_point2bn := Load_EC_POINT_point2bn;
  EC_POINT_bn2point := Load_EC_POINT_bn2point;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_point2hex := Load_EC_POINT_point2hex;
  EC_POINT_hex2point := Load_EC_POINT_hex2point;
  EC_POINT_add := Load_EC_POINT_add;
  EC_POINT_dbl := Load_EC_POINT_dbl;
  EC_POINT_invert := Load_EC_POINT_invert;
  EC_POINT_is_at_infinity := Load_EC_POINT_is_at_infinity;
  EC_POINT_is_on_curve := Load_EC_POINT_is_on_curve;
  EC_POINT_cmp := Load_EC_POINT_cmp;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_make_affine := Load_EC_POINT_make_affine;
  EC_POINTs_make_affine := Load_EC_POINTs_make_affine;
  EC_POINTs_mul := Load_EC_POINTs_mul;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EC_POINT_mul := Load_EC_POINT_mul;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_GROUP_precompute_mult := Load_EC_GROUP_precompute_mult;
  EC_GROUP_have_precompute_mult := Load_EC_GROUP_have_precompute_mult;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ECPKPARAMETERS_it := Load_ECPKPARAMETERS_it;
  ECPKPARAMETERS_new := Load_ECPKPARAMETERS_new;
  ECPKPARAMETERS_free := Load_ECPKPARAMETERS_free;
  ECPARAMETERS_it := Load_ECPARAMETERS_it;
  ECPARAMETERS_new := Load_ECPARAMETERS_new;
  ECPARAMETERS_free := Load_ECPARAMETERS_free;
  EC_GROUP_get_basis_type := Load_EC_GROUP_get_basis_type;
    {$ifndef  OPENSSL_NO_EC2M}
  EC_GROUP_get_trinomial_basis := Load_EC_GROUP_get_trinomial_basis;
  EC_GROUP_get_pentanomial_basis := Load_EC_GROUP_get_pentanomial_basis;
    {$endif} { OPENSSL_NO_EC2M}
  d2i_ECPKParameters := Load_d2i_ECPKParameters;
  i2d_ECPKParameters := Load_i2d_ECPKParameters;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ECPKParameters_print := Load_ECPKParameters_print;
        {$ifndef  OPENSSL_NO_STDIO}
  ECPKParameters_print_fp := Load_ECPKParameters_print_fp;
        {$endif} { OPENSSL_NO_STDIO}
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_KEY_new_ex := Load_EC_KEY_new_ex;
  EC_KEY_new := Load_EC_KEY_new;
  EC_KEY_get_flags := Load_EC_KEY_get_flags;
  EC_KEY_set_flags := Load_EC_KEY_set_flags;
  EC_KEY_clear_flags := Load_EC_KEY_clear_flags;
  EC_KEY_decoded_from_explicit_params := Load_EC_KEY_decoded_from_explicit_params;
  EC_KEY_new_by_curve_name_ex := Load_EC_KEY_new_by_curve_name_ex;
  EC_KEY_new_by_curve_name := Load_EC_KEY_new_by_curve_name;
  EC_KEY_free := Load_EC_KEY_free;
  EC_KEY_copy := Load_EC_KEY_copy;
  EC_KEY_dup := Load_EC_KEY_dup;
  EC_KEY_up_ref := Load_EC_KEY_up_ref;
  EC_KEY_get0_engine := Load_EC_KEY_get0_engine;
  EC_KEY_get0_group := Load_EC_KEY_get0_group;
  EC_KEY_set_group := Load_EC_KEY_set_group;
  EC_KEY_get0_private_key := Load_EC_KEY_get0_private_key;
  EC_KEY_set_private_key := Load_EC_KEY_set_private_key;
  EC_KEY_get0_public_key := Load_EC_KEY_get0_public_key;
  EC_KEY_set_public_key := Load_EC_KEY_set_public_key;
  EC_KEY_get_enc_flags := Load_EC_KEY_get_enc_flags;
  EC_KEY_set_enc_flags := Load_EC_KEY_set_enc_flags;
  EC_KEY_get_conv_form := Load_EC_KEY_get_conv_form;
  EC_KEY_set_conv_form := Load_EC_KEY_set_conv_form;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EC_KEY_set_ex_data := Load_EC_KEY_set_ex_data;
  EC_KEY_get_ex_data := Load_EC_KEY_get_ex_data;
  EC_KEY_set_asn1_flag := Load_EC_KEY_set_asn1_flag;
  EC_KEY_precompute_mult := Load_EC_KEY_precompute_mult;
  EC_KEY_generate_key := Load_EC_KEY_generate_key;
  EC_KEY_check_key := Load_EC_KEY_check_key;
  EC_KEY_can_sign := Load_EC_KEY_can_sign;
  EC_KEY_set_public_key_affine_coordinates := Load_EC_KEY_set_public_key_affine_coordinates;
  EC_KEY_key2buf := Load_EC_KEY_key2buf;
  EC_KEY_oct2key := Load_EC_KEY_oct2key;
  EC_KEY_oct2priv := Load_EC_KEY_oct2priv;
  EC_KEY_priv2oct := Load_EC_KEY_priv2oct;
  EC_KEY_priv2buf := Load_EC_KEY_priv2buf;
  d2i_ECPrivateKey := Load_d2i_ECPrivateKey;
  i2d_ECPrivateKey := Load_i2d_ECPrivateKey;
  d2i_ECParameters := Load_d2i_ECParameters;
  i2d_ECParameters := Load_i2d_ECParameters;
  o2i_ECPublicKey := Load_o2i_ECPublicKey;
  i2o_ECPublicKey := Load_i2o_ECPublicKey;
  ECParameters_print := Load_ECParameters_print;
  EC_KEY_print := Load_EC_KEY_print;
        {$ifndef  OPENSSL_NO_STDIO}
  ECParameters_print_fp := Load_ECParameters_print_fp;
  EC_KEY_print_fp := Load_EC_KEY_print_fp;
        {$endif} { OPENSSL_NO_STDIO}
  EC_KEY_OpenSSL := Load_EC_KEY_OpenSSL;
  EC_KEY_get_default_method := Load_EC_KEY_get_default_method;
  EC_KEY_set_default_method := Load_EC_KEY_set_default_method;
  EC_KEY_get_method := Load_EC_KEY_get_method;
  EC_KEY_set_method := Load_EC_KEY_set_method;
  EC_KEY_new_method := Load_EC_KEY_new_method;
  ECDH_KDF_X9_62 := Load_ECDH_KDF_X9_62;
  ECDH_compute_key := Load_ECDH_compute_key;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ECDSA_SIG_new := Load_ECDSA_SIG_new;
  ECDSA_SIG_free := Load_ECDSA_SIG_free;
  d2i_ECDSA_SIG := Load_d2i_ECDSA_SIG;
  i2d_ECDSA_SIG := Load_i2d_ECDSA_SIG;
  ECDSA_SIG_get0 := Load_ECDSA_SIG_get0;
  ECDSA_SIG_get0_r := Load_ECDSA_SIG_get0_r;
  ECDSA_SIG_get0_s := Load_ECDSA_SIG_get0_s;
  ECDSA_SIG_set0 := Load_ECDSA_SIG_set0;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ECDSA_do_sign := Load_ECDSA_do_sign;
  ECDSA_do_sign_ex := Load_ECDSA_do_sign_ex;
  ECDSA_do_verify := Load_ECDSA_do_verify;
  ECDSA_sign_setup := Load_ECDSA_sign_setup;
  ECDSA_sign := Load_ECDSA_sign;
  ECDSA_sign_ex := Load_ECDSA_sign_ex;
  ECDSA_verify := Load_ECDSA_verify;
  ECDSA_size := Load_ECDSA_size;
  EC_KEY_METHOD_new := Load_EC_KEY_METHOD_new;
  EC_KEY_METHOD_free := Load_EC_KEY_METHOD_free;
  EC_KEY_METHOD_set_init := Load_EC_KEY_METHOD_set_init;
  EC_KEY_METHOD_set_keygen := Load_EC_KEY_METHOD_set_keygen;
  EC_KEY_METHOD_set_compute_key := Load_EC_KEY_METHOD_set_compute_key;
  EC_KEY_METHOD_set_sign := Load_EC_KEY_METHOD_set_sign;
  EC_KEY_METHOD_set_verify := Load_EC_KEY_METHOD_set_verify;
  EC_KEY_METHOD_get_init := Load_EC_KEY_METHOD_get_init;
  EC_KEY_METHOD_get_keygen := Load_EC_KEY_METHOD_get_keygen;
  EC_KEY_METHOD_get_compute_key := Load_EC_KEY_METHOD_get_compute_key;
  EC_KEY_METHOD_get_sign := Load_EC_KEY_METHOD_get_sign;
  EC_KEY_METHOD_get_verify := Load_EC_KEY_METHOD_get_verify;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_EC}
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



