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
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}

function LEGACY_X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG;
begin
  Result := X509_NAME_hash_old(x);
end;

const
  ASIdentifierChoice_inherit = 0;
  ASIdentifierChoice_asIdsOrRanges = 1;
  SHA_DIGEST_LENGTH = 20;

type
  PSTACK= type pointer;
  PSTACK_OF_X509_EXTENSION = PSTACK; 
  _PX509_CINF = ^_X509_CINF;
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
    enc : TASN1_ENCODING;
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

  _PX509_CERT_AUX = pointer;
  
   _PX509 = ^X509;
   
   _X509_algor_st = record
    algorithm: PASN1_OBJECT;
    parameter: PASN1_TYPE;
  end; (* X509_ALGOR *)

  _PX509_ALGOR = ^_X509_ALGOR;
  _X509_ALGOR = _X509_algor_st;
  

  X509 = record
    cert_info: _PX509_CINF;
    sig_alg : _PX509_ALGOR;
    signature : PASN1_BIT_STRING;
    valid : TOpenSSL_C_INT;
    references : TOpenSSL_C_INT;
    name : PAnsiChar;
    ex_data : TCRYPTO_EX_DATA;
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
    aux : _PX509_CERT_AUX;
  end;   

procedure LEGACY_X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: _PX509_ALGOR; const x: PX509);
begin
  sig := _PX509(x)^.signature;
  alg := _PX509(x)^.sig_alg;
end;

function LEGACY_X509_get0_notBefore(const x: PX509): PASN1_TIME;
begin
  Result := _PX509(x)^.cert_info.validity.notBefore;
end;

function LEGACY_X509_get0_notAfter(const x: PX509): PASN1_TIME;
begin
  Result := _PX509(x)^.cert_info.validity.notAfter;
end;

function LEGACY_X509_get_signature_type(const x: PX509): TOpenSSL_C_INT;
begin
  Result := EVP_PKEY_type(OBJ_obj2nid(_PX509(x)^.sig_alg^.algorithm));
end;


{$endif}
{$endif}

