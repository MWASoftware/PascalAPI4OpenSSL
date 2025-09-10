(* This unit was generated from the source file x509v3.h2pas 
It should not be modified directly. All changes should be made to x509v3.h2pas
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


unit OpenSSL_x509v3;


interface

// Headers for OpenSSL 1.1.1
// x509v3.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_asn1,
  OpenSSL_asn1t,
  OpenSSL_safestack,
  OpenSSL_stack,
  OpenSSL_x509;

const
  (* ext_flags values *)
  X509V3_EXT_DYNAMIC      = $1;
  X509V3_EXT_CTX_DEP      = $2;
  X509V3_EXT_MULTILINE    = $4;

  // v3_ext_ctx
  CTX_TEST = $1;
  X509V3_CTX_REPLACE = $2;

  // GENERAL_NAME_st
  GEN_OTHERNAME   = 0;
  GEN_EMAIL       = 1;
  GEN_DNS         = 2;
  GEN_X400        = 3;
  GEN_DIRNAME     = 4;
  GEN_EDIPARTY    = 5;
  GEN_URI         = 6;
  GEN_IPADD       = 7;
  GEN_RID         = 8;

  (* All existing reasons *)
  CRLDP_ALL_REASONS       = $807f;

  CRL_REASON_NONE                         = -1;
  CRL_REASON_UNSPECIFIED                  = 0;
  CRL_REASON_KEY_COMPROMISE               = 1;
  CRL_REASON_CA_COMPROMISE                = 2;
  CRL_REASON_AFFILIATION_CHANGED          = 3;
  CRL_REASON_SUPERSEDED                   = 4;
  CRL_REASON_CESSATION_OF_OPERATION       = 5;
  CRL_REASON_CERTIFICATE_HOLD             = 6;
  CRL_REASON_REMOVE_FROM_CRL              = 8;
  CRL_REASON_PRIVILEGE_WITHDRAWN          = 9;
  CRL_REASON_AA_COMPROMISE                = 10;

  (* Values in idp_flags field *)
  (* IDP present *)
  IDP_PRESENT     = $1;
  (* IDP values inconsistent *)
  IDP_INVALID     = $2;
  (* onlyuser true *)
  IDP_ONLYUSER    = $4;
  (* onlyCA true *)
  IDP_ONLYCA      = $8;
  (* onlyattr true *)
  IDP_ONLYATTR    = $10;
  (* indirectCRL true *)
  IDP_INDIRECT    = $20;
  (* onlysomereasons present *)
  IDP_REASONS     = $40;

  EXT_END: array[0..13] of TOpenSSL_C_INT = (-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

  (* X509_PURPOSE stuff *)

  EXFLAG_BCONS            = $1;
  EXFLAG_KUSAGE           = $2;
  EXFLAG_XKUSAGE          = $4;
  EXFLAG_NSCERT           = $8;

  EXFLAG_CA               = $10;
  (* Really self issued not necessarily self signed *)
  EXFLAG_SI               = $20;
  EXFLAG_V1               = $40;
  EXFLAG_INVALID          = $80;
  (* EXFLAG_SET is set to indicate that some values have been precomputed *)
  EXFLAG_SET              = $100;
  EXFLAG_CRITICAL         = $200;
  EXFLAG_PROXY            = $400;

  EXFLAG_INVALID_POLICY   = $800;
  EXFLAG_FRESHEST         = $1000;
  (* Self signed *)
  EXFLAG_SS               = $2000;

  KU_DIGITAL_SIGNATURE    = $0080;
  KU_NON_REPUDIATION      = $0040;
  KU_KEY_ENCIPHERMENT     = $0020;
  KU_DATA_ENCIPHERMENT    = $0010;
  KU_KEY_AGREEMENT        = $0008;
  KU_KEY_CERT_SIGN        = $0004;
  KU_CRL_SIGN             = $0002;
  KU_ENCIPHER_ONLY        = $0001;
  KU_DECIPHER_ONLY        = $8000;

  NS_SSL_CLIENT           = $80;
  NS_SSL_SERVER           = $40;
  NS_SMIME                = $20;
  NS_OBJSIGN              = $10;
  NS_SSL_CA               = $04;
  NS_SMIME_CA             = $02;
  NS_OBJSIGN_CA           = $01;
  NS_ANY_CA               = NS_SSL_CA or NS_SMIME_CA or NS_OBJSIGN_CA;

  XKU_SSL_SERVER          = $1;
  XKU_SSL_CLIENT          = $2;
  XKU_SMIME               = $4;
  XKU_CODE_SIGN           = $8;
  XKU_SGC                 = $10;
  XKU_OCSP_SIGN           = $20;
  XKU_TIMESTAMP           = $40;
  XKU_DVCS                = $80;
  XKU_ANYEKU              = $100;

  X509_PURPOSE_DYNAMIC    = $1;
  X509_PURPOSE_DYNAMIC_NAME       = $2;

  X509_PURPOSE_SSL_CLIENT         = 1;
  X509_PURPOSE_SSL_SERVER         = 2;
  X509_PURPOSE_NS_SSL_SERVER      = 3;
  X509_PURPOSE_SMIME_SIGN         = 4;
  X509_PURPOSE_SMIME_ENCRYPT      = 5;
  X509_PURPOSE_CRL_SIGN           = 6;
  X509_PURPOSE_ANY                = 7;
  X509_PURPOSE_OCSP_HELPER        = 8;
  X509_PURPOSE_TIMESTAMP_SIGN     = 9;

  X509_PURPOSE_MIN                = 1;
  X509_PURPOSE_MAX                = 9;

  (* Flags for X509V3_EXT_print() *)

  X509V3_EXT_UNKNOWN_MASK         = TOpenSSL_C_LONG($f) shl 16;
  (* Return error for unknown extensions *)
  X509V3_EXT_DEFAULT              = 0;
  (* Print error for unknown extensions *)
  X509V3_EXT_ERROR_UNKNOWN        = TOpenSSL_C_LONG(1) shl 16;
  (* ASN1 parse unknown extensions *)
  X509V3_EXT_PARSE_UNKNOWN        = TOpenSSL_C_LONG(2) shl 16;
  (* BIO_dump unknown extensions *)
  X509V3_EXT_DUMP_UNKNOWN         = TOpenSSL_C_LONG(3) shl 16;

  (* Flags for X509V3_add1_i2d *)

  X509V3_ADD_OP_MASK              = TOpenSSL_C_LONG($f);
  X509V3_ADD_DEFAULT              = TOpenSSL_C_LONG(0);
  X509V3_ADD_APPEND               = TOpenSSL_C_LONG(1);
  X509V3_ADD_REPLACE              = TOpenSSL_C_LONG(2);
  X509V3_ADD_REPLACE_EXISTING     = TOpenSSL_C_LONG(3);
  X509V3_ADD_KEEP_EXISTING        = TOpenSSL_C_LONG(4);
  X509V3_ADD_DELETE               = TOpenSSL_C_LONG(5);
  X509V3_ADD_SILENT               = $10;

  (* Flags for X509_check_* functions *)

  (*
   * Always check subject name for host match even if subject alt names present
   *)
  X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT    = $1;
  (* Disable wildcard matching for dnsName fields and common name. *)
  X509_CHECK_FLAG_NO_WILDCARDS    = $2;
  (* Wildcards must not match a partial label. *)
  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = $4;
  (* Allow (non-partial) wildcards to match multiple labels. *)
  X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = $8;
  (* Constraint verifier subdomain patterns to match a single labels. *)
  X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = $10;
  (* Never check the subject CN *)
  X509_CHECK_FLAG_NEVER_CHECK_SUBJECT    = $20;
  (*
   * Match reference identifiers starting with "." to any sub-domain.
   * This is a non-public flag, turned on implicitly when the subject
   * reference identity is a DNS name.
   *)
  _X509_CHECK_FLAG_DOT_SUBDOMAINS = $8000;

  ASIdOrRange_id          = 0;
  ASIdOrRange_range       = 1;

  ASIdentifierChoice_inherit              = 0;
  ASIdentifierChoice_asIdsOrRanges        = 1;

  IPAddressOrRange_addressPrefix  = 0;
  IPAddressOrRange_addressRange   = 1;

  IPAddressChoice_inherit                 = 0;
  IPAddressChoice_addressesOrRanges       = 1;

  (*
   * API tag for elements of the ASIdentifer SEQUENCE.
   *)
  V3_ASID_ASNUM   = 0;
  V3_ASID_RDI     = 1;

  (*
   * AFI values, assigned by IANA.  It'd be nice to make the AFI
   * handling code totally generic, but there are too many little things
   * that would need to be defined for other address families for it to
   * be worth the trouble.
   *)
  IANA_AFI_IPV4   = 1;
  IANA_AFI_IPV6   = 2;

type
  (* Forward reference *)
  //Pv3_ext_method = ^v3_ext_method;
  //Pv3_ext_ctx = ^v3_ext_ctx;

  (* Useful typedefs *)

  //X509V3_EXT_NEW = function: Pointer; cdecl;
  //X509V3_EXT_FREE = procedure(v1: Pointer); cdecl;
  //X509V3_EXT_D2I = function(v1: Pointer; v2: PPByte; v3: TOpenSSL_C_Long): Pointer; cdecl;
  //X509V3_EXT_I2D = function(v1: Pointer; v2: PPByte): TOpenSSL_C_INT; cdecl;
//  typedef STACK_OF(CONF_VALUE) *
//      (*X509V3_EXT_I2V) (const struct v3_ext_method *method, void *ext,
//                         STACK_OF(CONF_VALUE) *extlist);
//  typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
//                                  struct v3_ext_ctx *ctx,
//                                  STACK_OF(CONF_VALUE) *values);
  //X509V3_EXT_I2S = function(method: Pv3_ext_method; ext: Pointer): PAnsiChar; cdecl;
  //X509V3_EXT_S2I = function(method: Pv3_ext_method; ctx: Pv3_ext_ctx; const str: PAnsiChar): Pointer; cdecl;
  //X509V3_EXT_I2R = function(const method: Pv3_ext_method; ext: Pointer; out_: PBIO; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  //X509V3_EXT_R2I = function(const method: Pv3_ext_method; ctx: Pv3_ext_ctx; const str: PAnsiChar): Pointer; cdecl;

//  (* V3 extension structure *)
//  v3_ext_method = record
//    ext_nid: TOpenSSL_C_INT;
//    ext_flags: TOpenSSL_C_INT;
//(* If this is set the following four fields are ignored *)
//    it: PASN1_ITEM_EXP;
//(* Old style ASN1 calls *)
//    ext_new: X509V3_EXT_NEW;
//    ext_free: X509V3_EXT_FREE;
//    d2i: X509V3_EXT_D2I;
//    i2d: X509V3_EXT_I2D;
//(* The following pair is used for string extensions *)
//    i2s: X509V3_EXT_I2S;
//    s2i: X509V3_EXT_S2I;
//(* The following pair is used for multi-valued extensions *)
//    i2v: X509V3_EXT_I2V;
//    v2i: X509V3_EXT_V2I;
//(* The following are used for raw extensions *)
//    i2r: X509V3_EXT_I2R;
//    r2i: X509V3_EXT_R2I;
//    usr_data: Pointer;             (* Any extension specific data *)
//  end;
//  X509V3_EXT_METHOD = v3_ext_method;
//  PX509V3_EXT_METHOD = ^X509V3_EXT_METHOD;
//  DEFINE_STACK_OF(X509V3_EXT_METHOD)

//  typedef struct X509V3_CONF_METHOD_st {
//      PAnsiChar *(*get_string) (void *db, const section: PAnsiChar, const value: PAnsiChar);
//      STACK_OF(CONF_VALUE) *(*get_section) (void *db, const section: PAnsiChar);
//      void (*free_string) (void *db, PAnsiChar *string);
//      void (*free_section) (void *db, STACK_OF(CONF_VALUE) *section);
//  } X509V3_CONF_METHOD;

// Moved to ossl_typ
//  (* Context specific info *)
//  v3_ext_ctx = record
//    flags: TOpenSSL_C_INT;
//    issuer_cert: PX509;
//    subject_cert: PX509;
//    subject_req: PX509_REQ;
//    crl: PX509_CRL;
//    db_meth: PX509V3_CONF_METHOD;
//    db: Pointer;
//  (* Maybe more here *)
//  end;

  ENUMERATED_NAMES = BIT_STRING_BITNAME;

  BASIC_CONSTRAINTS_st = record
    ca: TOpenSSL_C_INT;
    pathlen: PASN1_INTEGER;
  end;
  BASIC_CONSTRAINTS = BASIC_CONSTRAINTS_st;
  PBASIC_CONSTRAINTS = ^BASIC_CONSTRAINTS;

  PKEY_USAGE_PERIOD_st = record
    notBefore: PASN1_GENERALIZEDTIME;
    notAfter: PASN1_GENERALIZEDTIME;
  end;
  PKEY_USAGE_PERIOD = PKEY_USAGE_PERIOD_st;
  PPKEY_USAGE_PERIOD = ^PKEY_USAGE_PERIOD;

  otherName_st = record
    type_id: PASN1_OBJECT;
    value: PASN1_TYPE;
  end;
  OTHERNAME = otherName_st;
  POTHERNAME = ^OTHERNAME;

  EDIPartyName_st  = record
    nameAssigner: PASN1_STRING;
    partyName: PASN1_STRING;
  end;
  EDIPARTYNAME = EDIPartyName_st;
  PEDIPARTYNAME = ^EDIPARTYNAME;

  GENERAL_NAME_st_union = record
    case TOpenSSL_C_INT of
      0: (ptr: PAnsiChar);
      1: (otherName: POTHERNAME);   (* otherName *)
      2: (rfc822Name: PASN1_IA5STRING);
      3: (dNSName: PASN1_IA5STRING);
      4: (x400Address: PASN1_TYPE);
      5: (directoryName: PX509_NAME);
      6: (ediPartyName: PEDIPARTYNAME);
      7: (uniformResourceIdentifier: PASN1_IA5STRING);
      8: (iPAddress: PASN1_OCTET_STRING);
      9: (registeredID: PASN1_OBJECT);
      (* Old names *)
      10: (ip: PASN1_OCTET_STRING);  (* iPAddress *)
      11: (dirn: PX509_NAME);        (* dirn *)
      12: (ia5: PASN1_IA5STRING);    (* rfc822Name, dNSName,
                                      * uniformResourceIdentifier *)
      13: (rid: PASN1_OBJECT);       (* registeredID *)
      14: (other: PASN1_TYPE);       (* x400Address *)
  end;
  GENERAL_NAME_st = record
    type_: TOpenSSL_C_INT;
    d: GENERAL_NAME_st_union;
  end;
  GENERAL_NAME = GENERAL_NAME_st;
  PGENERAL_NAME = ^GENERAL_NAME;

  PSTACK_OF_GENERAL_NAME = Pointer;
  PGENERAL_NAMES = PSTACK_OF_GENERAL_NAME;

  ACCESS_DESCRIPTION_st = record
    method: PASN1_OBJECT;
    location: PGENERAL_NAME;
  end;
  ACCESS_DESCRIPTION = ACCESS_DESCRIPTION_st;
  PACCESS_DESCRIPTION = ^ACCESS_DESCRIPTION;

//  typedef STACK_OF(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;

//  typedef STACK_OF(ASN1_OBJECT) EXTENDED_KEY_USAGE;

//  typedef STACK_OF(ASN1_INTEGER) TLS_FEATURE;

//  DEFINE_STACK_OF(GENERAL_NAME)
//  typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;
//  DEFINE_STACK_OF(GENERAL_NAMES)

//  DEFINE_STACK_OF(ACCESS_DESCRIPTION)
//  DIST_POINT_NAME_st_union = record
//    case TOpenSSL_C_INT of
//      0: (GENERAL_NAMES *fullname);
//      1: (STACK_OF(X509_NAME_ENTRY) *relativename);
//  end;
  DIST_POINT_NAME_st = record
    type_: TOpenSSL_C_INT;
    (* If relativename then this contains the full distribution point name *)
    dpname: PX509_NAME;
  end;
  DIST_POINT_NAME = DIST_POINT_NAME_st;
  PDIST_POINT_NAME = ^DIST_POINT_NAME;


//  struct DIST_POINT_ST {
//      DIST_POINT_NAME *distpoint;
//      ASN1_BIT_STRING *reasons;
//      GENERAL_NAMES *CRLissuer;
//      TOpenSSL_C_INT dp_reasons;
//  };

//  typedef STACK_OF(DIST_POINT) CRL_DIST_POINTS;

//  DEFINE_STACK_OF(DIST_POINT)

//  AUTHORITY_KEYID_st = record
//    keyid: PASN1_OCTET_STRING;
//    issuer: PGENERAL_NAMES;
//    serial: PASN1_INTEGER;
//  end;

  (* Strong extranet structures *)

  SXNET_ID_st = record
    zone: PASN1_INTEGER;
    user: PASN1_OCTET_STRING;
  end;
  SXNETID = SXNET_ID_st;
  PSXNETID = ^SXNETID;
//  DEFINE_STACK_OF(SXNETID)

//  SXNET_st = record
//    ASN1_INTEGER *version;
//    STACK_OF(SXNETID) *ids;
//  end;
//  SXNET = SXNET_st;
//  PSXNET = ^SXNET;

//  NOTICEREF_st = record
//    ASN1_STRING *organization;
//    STACK_OF(ASN1_INTEGER) *noticenos;
//  end;
//  NOTICEREF = NOTICEREF_st;
//  PNOTICEREF = ^NOTICEREF;

//  USERNOTICE_st = record
//    noticeref: PNOTICEREF;
//    exptext: PASN1_STRING;
//  end;
//  USERNOTICE = USERNOTICE_st;
//  PUSERNOTICE = ^USERNOTICE;

//  POLICYQUALINFO_st_union = record
//    case TOpenSSL_C_INT of
//      0: (cpsuri: PASN1_IA5STRING);
//      1: (usernotice: PUSERNOTICE);
//      2: (other: PASN1_TYPE);
//  end;
//  POLICYQUALINFO_st = record
//    pqualid: PASN1_OBJECT;
//    d: POLICYQUALINFO_st_union;
//  end;
//  POLICYQUALINFO = POLICYQUALINFO_st;
//  PPOLICYQUALINFO = ^POLICYQUALINFO;
//  DEFINE_STACK_OF(POLICYQUALINFO)

//  POLICYINFO_st = record
//    ASN1_OBJECT *policyid;
//    STACK_OF(POLICYQUALINFO) *qualifiers;
//  end;
//  POLICYINFO = POLICYINFO_st;
//  PPOLICYINFO = ^POLICYINFO;
//  typedef STACK_OF(POLICYINFO) CERTIFICATEPOLICIES;
//  DEFINE_STACK_OF(POLICYINFO)

  POLICY_MAPPING_st = record
    issuerDomainPolicy: PASN1_OBJECT;
    subjectDomainPolicy: PASN1_OBJECT;
  end;
  POLICY_MAPPING = POLICY_MAPPING_st;
  PPOLICY_MAPPING = ^POLICY_MAPPING;
//  DEFINE_STACK_OF(POLICY_MAPPING)
//  typedef STACK_OF(POLICY_MAPPING) POLICY_MAPPINGS;

  GENERAL_SUBTREE_st = record
    base: PGENERAL_NAME;
    minimum: PASN1_INTEGER;
    maximum: PASN1_INTEGER;
  end;
  GENERAL_SUBTREE = GENERAL_SUBTREE_st;
  PGENERAL_SUBTREE = ^GENERAL_SUBTREE;
//  DEFINE_STACK_OF(GENERAL_SUBTREE)

//  NAME_CONSTRAINTS_st = record
//    STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
//    STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
//  end;

  POLICY_CONSTRAINTS_st = record
    requireExplicitPolicy: PASN1_INTEGER;
    inhibitPolicyMapping: PASN1_INTEGER;
  end;
  POLICY_CONSTRAINTS = POLICY_CONSTRAINTS_st;
  PPOLICY_CONSTRAINTS = ^POLICY_CONSTRAINTS;

  (* Proxy certificate structures, see RFC 3820 *)
  PROXY_POLICY_st = record
    policyLanguage: PASN1_OBJECT;
    policy: PASN1_OCTET_STRING;
  end;
  PROXY_POLICY = PROXY_POLICY_st;
  PPROXY_POLICY = ^PROXY_POLICY;
//  DECLARE_ASN1_FUNCTIONS(PROXY_POLICY)

  PROXY_CERT_INFO_EXTENSION_st = record
    pcPathLengthConstraint: PASN1_INTEGER;
    proxyPolicy: PPROXY_POLICY;
  end;
  PROXY_CERT_INFO_EXTENSION = PROXY_CERT_INFO_EXTENSION_st;
  PPROXY_CERT_INFO_EXTENSION = ^PROXY_CERT_INFO_EXTENSION;
//  DECLARE_ASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)

//  ISSUING_DIST_POint_st = record
//    distpoint: PDIST_POINT_NAME;
//    TOpenSSL_C_INT onlyuser;
//    TOpenSSL_C_INT onlyCA;
//    onlysomereasons: PASN1_BIT_STRING;
//    TOpenSSL_C_INT indirectCRL;
//    TOpenSSL_C_INT onlyattr;
//  end;

//  # define X509V3_conf_err(val) ERR_add_error_data(6, \
//                          "section:", (val)->section, \
//                          ",name:", (val)->name, ",value:", (val)->value)
//
//  # define X509V3_set_ctx_test(ctx) \
//                          X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, CTX_TEST)
//  # define X509V3_set_ctx_nodb(ctx) (ctx)->db = NULL;
//
//  # define EXT_BITSTRING(nid, table) { nid, 0, ASN1_ITEM_ref(ASN1_BIT_STRING), \
//                          0,0,0,0, \
//                          0,0, \
//                          (X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \
//                          (X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \
//                          NULL, NULL, \
//                          table}
//
//  # define EXT_IA5STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_IA5STRING), \
//                          0,0,0,0, \
//                          (X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \
//                          (X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \
//                          0,0,0,0, \
//                          NULL}
                         
  PX509_PURPOSE = ^X509_PURPOSE;
  x509_purpose_st = record
    purpose: TOpenSSL_C_INT;
    trust: TOpenSSL_C_INT;                  (* Default trust ID *)
    flags: TOpenSSL_C_INT;
    check_purpose: function(const v1: PX509_PURPOSE; const v2: PX509; v3: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
    name: PAnsiChar;
    sname: PAnsiChar;
    usr_data: Pointer;
  end;
  X509_PURPOSE = x509_purpose_st;
//  DEFINE_STACK_OF(X509_PURPOSE)

//  DECLARE_ASN1_FUNCTIONS(SXNET)
//  DECLARE_ASN1_FUNCTIONS(SXNETID)

type
  ASRange_st = record
    min, max: PASN1_INTEGER;
  end;
  ASRange = ASRange_st;
  PASRange = ^ASRange;

  ASIdOrRange_st = record
    type_: TOpenSSL_C_INT;
    case u: TOpenSSL_C_INT of
      0: (id: PASN1_INTEGER);
      1: (range: PASRange);
  end;
  ASIdOrRange = ASIdOrRange_st;
  PASIdOrRange = ^ASIdOrRange;
//  typedef STACK_OF(ASIdOrRange) ASIdOrRanges;
//  DEFINE_STACK_OF(ASIdOrRange)

//  ASIdentifierChoice_st = record
//    type_: TOpenSSL_C_INT;
//    case u: TOpenSSL_C_INT of
//      0: (inherit: PASN1_NULL);
//      1: (asIdsOrRanges: PASIdOrRanges);
//  end;
//  ASIdentifierChoice = ASIdentifierChoice_st;
//  PASIdentifierChoice = ^ASIdentifierChoice;

//  ASIdentifiers_st = record
//    asnum, rdi: PASIdentifierChoice;
//  end;
//  ASIdentifiers = ASIdentifiers_st;
//  PASIdentifiers = ^ASIdentifiers;

//  DECLARE_ASN1_FUNCTIONS(ASRange)
//  DECLARE_ASN1_FUNCTIONS(ASIdOrRange)
//  DECLARE_ASN1_FUNCTIONS(ASIdentifierChoice)
//  DECLARE_ASN1_FUNCTIONS(ASIdentifiers)

  IPAddressRange_st = record
    min, max: PASN1_BIT_STRING;
  end;
  IPAddressRange = IPAddressRange_st;
  PIPAddressRange = ^IPAddressRange;

  IPAddressOrRange_st = record
    type_: TOpenSSL_C_INT;
    case u: TOpenSSL_C_INT of
      0: (addressPrefix: PASN1_BIT_STRING);
      1: (addressRange: PIPAddressRange);
  end;
  IPAddressOrRange = IPAddressOrRange_st;
  PIPAddressOrRange = ^IPAddressOrRange;

//  typedef STACK_OF(IPAddressOrRange) IPAddressOrRanges;
//  DEFINE_STACK_OF(IPAddressOrRange)

//  IPAddressChoice_st = record
//    type_: TOpenSSL_C_INT;
//    case u: TOpenSSL_C_INT of
//      0: (inherit: PASN1_NULL);
//      1: (addressesOrRanges: PIPAddressOrRanges);
//  end;
//  IPAddressChoice = IPAddressChoice_st;
//  PIPAddressChoice = ^IPAddressChoice;

//  IPAddressFamily_st = record
//    addressFamily: PASN1_OCTET_STRING;
//    ipAddressChoice: PIPAddressChoice;
//  end;
//  IPAddressFamily = IPAddressFamily_st;
//  PIPAddressFamily = ^IPAddressFamily;

//  typedef STACK_OF(IPAddressFamily) IPAddrBlocks;
//  DEFINE_STACK_OF(IPAddressFamily)

//  DECLARE_ASN1_FUNCTIONS(IPAddressRange)
//  DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)
//  DECLARE_ASN1_FUNCTIONS(IPAddressChoice)
//  DECLARE_ASN1_FUNCTIONS(IPAddressFamily)

  NamingAuthority_st = type Pointer;
  NAMING_AUTHORITY = NamingAuthority_st;
  PNAMING_AUTHORITY = ^NAMING_AUTHORITY;
  
  ProfessionInfo_st = type Pointer;
  PROFESSION_INFO = ProfessionInfo_st;
  PPROFESSION_INFO = ^PROFESSION_INFO;
  
  Admissions_st = type Pointer;
  ADMISSIONS = Admissions_st;
  PADMISSIONS = ^ADMISSIONS;
  
  AdmissionSyntax_st = type Pointer;
  ADMISSION_SYNTAX = AdmissionSyntax_st;
  PADMISSION_SYNTAX = ^ADMISSION_SYNTAX;
//  DECLARE_ASN1_FUNCTIONS(NAMING_AUTHORITY)
//  DECLARE_ASN1_FUNCTIONS(PROFESSION_INFO)
//  DECLARE_ASN1_FUNCTIONS(ADMISSIONS)
//  DECLARE_ASN1_FUNCTIONS(ADMISSION_SYNTAX)
//  DEFINE_STACK_OF(ADMISSIONS)
//  DEFINE_STACK_OF(PROFESSION_INFO)
//  typedef STACK_OF(PROFESSION_INFO) PROFESSION_INFOS;

//  function SXNET_add_id_asc(psx: PPSXNET; const zone: PAnsiChar; const user: PAnsiChar; userlen: TOpenSSL_C_INT): TOpenSSL_C_INT;
//  function SXNET_add_id_ulong(psx: PPSXNET; lzone: TOpenSSL_C_ULONG; const user: PAnsiChar; userlen: TOpenSSL_C_INT): TOpenSSL_C_INT;
//  function SXNET_add_id_INTEGER(psx: PPSXNET; izone: PASN1_INTEGER; const user: PAnsiChar; userlen: TOpenSSL_C_INT): TOpenSSL_C_INT;

//  function SXNET_get_id_asc(sx: PSXNET; const zone: PAnsiChar): PASN1_OCTET_STRING;
//  function SXNET_get_id_ulong(sx: PSXNET; lzone: TOpenSSL_C_ULONG): PASN1_OCTET_STRING;
//  function SXNET_get_id_INTEGER(sx: PSXNET; zone: PASN1_INTEGER): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS_st)

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BASIC_CONSTRAINTS_free}
{$EXTERNALSYM BASIC_CONSTRAINTS_new}
{$EXTERNALSYM AUTHORITY_KEYID_free}
{$EXTERNALSYM AUTHORITY_KEYID_new}
{$EXTERNALSYM GENERAL_NAME_free}
{$EXTERNALSYM GENERAL_NAME_new}
{$EXTERNALSYM GENERAL_NAME_cmp}
{$EXTERNALSYM GENERAL_NAME_print}
{$EXTERNALSYM GENERAL_NAMES_free}
{$EXTERNALSYM GENERAL_NAMES_new}
{$EXTERNALSYM OTHERNAME_cmp}
{$EXTERNALSYM GENERAL_NAME_set0_value}
{$EXTERNALSYM GENERAL_NAME_get0_value}
{$EXTERNALSYM GENERAL_NAME_set0_othername}
{$EXTERNALSYM GENERAL_NAME_get0_otherName}
{$EXTERNALSYM i2a_ACCESS_DESCRIPTION}
{$EXTERNALSYM DIST_POINT_set_dpname}
{$EXTERNALSYM NAME_CONSTRAINTS_check}
{$EXTERNALSYM NAME_CONSTRAINTS_check_CN}
{$EXTERNALSYM X509V3_EXT_nconf_nid}
{$EXTERNALSYM X509V3_EXT_nconf}
{$EXTERNALSYM X509V3_EXT_add_nconf}
{$EXTERNALSYM X509V3_EXT_REQ_add_nconf}
{$EXTERNALSYM X509V3_EXT_CRL_add_nconf}
{$EXTERNALSYM X509V3_EXT_conf_nid}
{$EXTERNALSYM X509V3_EXT_conf}
{$EXTERNALSYM X509V3_EXT_add_conf}
{$EXTERNALSYM X509V3_EXT_REQ_add_conf}
{$EXTERNALSYM X509V3_EXT_CRL_add_conf}
{$EXTERNALSYM X509V3_set_nconf}
{$EXTERNALSYM X509V3_get_string}
{$EXTERNALSYM X509V3_string_free}
{$EXTERNALSYM X509V3_set_ctx}
{$EXTERNALSYM X509V3_EXT_add_alias}
{$EXTERNALSYM X509V3_EXT_cleanup}
{$EXTERNALSYM X509V3_add_standard_extensions}
{$EXTERNALSYM X509V3_EXT_d2i}
{$EXTERNALSYM X509V3_EXT_i2d}
{$EXTERNALSYM X509V3_EXT_print}
{$EXTERNALSYM X509_check_ca}
{$EXTERNALSYM X509_check_purpose}
{$EXTERNALSYM X509_supported_extension}
{$EXTERNALSYM X509_PURPOSE_set}
{$EXTERNALSYM X509_check_issued}
{$EXTERNALSYM X509_check_akid}
{$EXTERNALSYM X509_set_proxy_flag}
{$EXTERNALSYM X509_set_proxy_pathlen}
{$EXTERNALSYM X509_get_proxy_pathlen}
{$EXTERNALSYM X509_get_extension_flags}
{$EXTERNALSYM X509_get_key_usage}
{$EXTERNALSYM X509_get_extended_key_usage}
{$EXTERNALSYM X509_get0_subject_key_id}
{$EXTERNALSYM X509_get0_authority_key_id}
{$EXTERNALSYM X509_get0_authority_serial}
{$EXTERNALSYM X509_PURPOSE_get_count}
{$EXTERNALSYM X509_PURPOSE_get0}
{$EXTERNALSYM X509_PURPOSE_get_by_sname}
{$EXTERNALSYM X509_PURPOSE_get_by_id}
{$EXTERNALSYM X509_PURPOSE_get0_name}
{$EXTERNALSYM X509_PURPOSE_get0_sname}
{$EXTERNALSYM X509_PURPOSE_get_trust}
{$EXTERNALSYM X509_PURPOSE_cleanup}
{$EXTERNALSYM X509_PURPOSE_get_id}
{$EXTERNALSYM X509_get1_email}
{$EXTERNALSYM X509_REQ_get1_email}
{$EXTERNALSYM X509_email_free}
{$EXTERNALSYM X509_get1_ocsp}
{$EXTERNALSYM X509_check_host}
{$EXTERNALSYM X509_check_email}
{$EXTERNALSYM X509_check_ip}
{$EXTERNALSYM X509_check_ip_asc}
{$EXTERNALSYM a2i_IPADDRESS}
{$EXTERNALSYM a2i_IPADDRESS_NC}
{$EXTERNALSYM X509_POLICY_NODE_print}
{$EXTERNALSYM X509v3_addr_get_range}
{$EXTERNALSYM X509v3_asid_validate_path}
{$EXTERNALSYM X509v3_addr_validate_path}
{$EXTERNALSYM NAMING_AUTHORITY_get0_authorityId}
{$EXTERNALSYM NAMING_AUTHORITY_get0_authorityURL}
{$EXTERNALSYM NAMING_AUTHORITY_get0_authorityText}
{$EXTERNALSYM NAMING_AUTHORITY_set0_authorityId}
{$EXTERNALSYM NAMING_AUTHORITY_set0_authorityURL}
{$EXTERNALSYM NAMING_AUTHORITY_set0_authorityText}
{$EXTERNALSYM ADMISSION_SYNTAX_get0_admissionAuthority}
{$EXTERNALSYM ADMISSION_SYNTAX_set0_admissionAuthority}
{$EXTERNALSYM ADMISSIONS_get0_admissionAuthority}
{$EXTERNALSYM ADMISSIONS_set0_admissionAuthority}
{$EXTERNALSYM ADMISSIONS_get0_namingAuthority}
{$EXTERNALSYM ADMISSIONS_set0_namingAuthority}
{$EXTERNALSYM PROFESSION_INFO_get0_addProfessionInfo}
{$EXTERNALSYM PROFESSION_INFO_set0_addProfessionInfo}
{$EXTERNALSYM PROFESSION_INFO_get0_namingAuthority}
{$EXTERNALSYM PROFESSION_INFO_set0_namingAuthority}
{$EXTERNALSYM PROFESSION_INFO_get0_registrationNumber}
{$EXTERNALSYM PROFESSION_INFO_set0_registrationNumber}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure BASIC_CONSTRAINTS_free(bc : PBASIC_CONSTRAINTS); cdecl; external CLibCrypto;
function BASIC_CONSTRAINTS_new: PBASIC_CONSTRAINTS; cdecl; external CLibCrypto;
procedure AUTHORITY_KEYID_free(id : AUTHORITY_KEYID); cdecl; external CLibCrypto;
function AUTHORITY_KEYID_new: AUTHORITY_KEYID; cdecl; external CLibCrypto;
procedure GENERAL_NAME_free(a: PGENERAL_NAME); cdecl; external CLibCrypto;
function GENERAL_NAME_new: PGENERAL_NAME; cdecl; external CLibCrypto;
function GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function GENERAL_NAME_print(out_: PBIO; gen: PGENERAL_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure GENERAL_NAMES_free(a: PGENERAL_NAMES); cdecl; external CLibCrypto;
function GENERAL_NAMES_new: PGENERAL_NAMES; cdecl; external CLibCrypto;
function OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure GENERAL_NAME_set0_value(a: PGENERAL_NAME; type_: TOpenSSL_C_INT; value: Pointer); cdecl; external CLibCrypto;
function GENERAL_NAME_get0_value(const a: PGENERAL_NAME; ptype: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function GENERAL_NAME_get0_otherName(const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ACCESS_DESCRIPTION(bp: PBIO; const a: PACCESS_DESCRIPTION): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TOpenSSL_C_INT; const value: PAnsiChar): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; const name: PAnsiChar; const value: PAnsiChar): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509V3_EXT_conf_nid(conf: Pointer; ctx: PX509V3_CTX; ext_nid: TOpenSSL_C_INT; const value: PAnsiChar): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509V3_EXT_conf(conf: Pointer; ctx: PX509V3_CTX; const name: PAnsiChar; const value: PAnsiChar): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509V3_EXT_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509V3_EXT_REQ_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509V3_EXT_CRL_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF); cdecl; external CLibCrypto;
function X509V3_get_string(ctx: PX509V3_CTX; const name: PAnsiChar; const section: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
procedure X509V3_string_free(ctx: PX509V3_CTX; str: PAnsiChar); cdecl; external CLibCrypto;
procedure X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function X509V3_EXT_add_alias(nid_to: TOpenSSL_C_INT; nid_from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509V3_EXT_cleanup; cdecl; external CLibCrypto;
function X509V3_add_standard_extensions: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer; cdecl; external CLibCrypto;
function X509V3_EXT_i2d(ext_nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509V3_EXT_print(out_: PBIO; ext: PX509_EXTENSION; flag: TOpenSSL_C_ULONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_ca(x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_purpose(x: PX509; id: TOpenSSL_C_INT; ca: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_supported_extension(ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PURPOSE_set(p: POpenSSL_C_INT; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_issued(issuer: PX509; subject: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_set_proxy_flag(x: PX509); cdecl; external CLibCrypto;
procedure X509_set_proxy_pathlen(x: PX509; l: TOpenSSL_C_LONG); cdecl; external CLibCrypto;
function X509_get_proxy_pathlen(x: PX509): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function X509_get_extension_flags(x: PX509): TOpenSSL_C_UINT32; cdecl; external CLibCrypto;
function X509_get_key_usage(x: PX509): TOpenSSL_C_UINT32; cdecl; external CLibCrypto;
function X509_get_extended_key_usage(x: PX509): TOpenSSL_C_UINT32; cdecl; external CLibCrypto;
function X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function X509_get0_authority_serial(x: PX509): PASN1_INTEGER; cdecl; external CLibCrypto;
function X509_PURPOSE_get_count: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PURPOSE_get0(idx: TOpenSSL_C_INT): PX509_PURPOSE; cdecl; external CLibCrypto;
function X509_PURPOSE_get_by_sname(const sname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PURPOSE_get_by_id(id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PURPOSE_get0_name(const xp: PX509_PURPOSE): PAnsiChar; cdecl; external CLibCrypto;
function X509_PURPOSE_get0_sname(const xp: PX509_PURPOSE): PAnsiChar; cdecl; external CLibCrypto;
function X509_PURPOSE_get_trust(const xp: PX509_PURPOSE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_PURPOSE_cleanup; cdecl; external CLibCrypto;
function X509_PURPOSE_get_id(const v1: PX509_PURPOSE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get1_email(x: PX509): PSTACK_OF_OPENSSL_STRING; cdecl; external CLibCrypto;
function X509_REQ_get1_email( x : PX509_REQ): PSTACK_OF_OPENSSL_STRING; cdecl; external CLibCrypto;
procedure X509_email_free(sk : PSTACK_OF_OPENSSL_STRING); cdecl; external CLibCrypto;
function X509_get1_ocsp(x: PX509): PSTACK_OF_OPENSSL_STRING; cdecl; external CLibCrypto;
function X509_check_host(x: PX509; const chk: PAnsiChar; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT; peername: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_email(x: PX509; const chk: PAnsiChar; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_ip(x: PX509; const chk: PByte; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_ip_asc(x: PX509; const ipasc: PAnsiChar; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2i_IPADDRESS(const ipasc: PAnsiChar): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function a2i_IPADDRESS_NC(const ipasc: PAnsiChar): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
procedure X509_POLICY_NODE_print(out_: PBIO; node: PX509_POLICY_NODE; indent: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function X509v3_addr_get_range(aor: PIPAddressOrRange; const afi: TOpenSSL_C_UINT; min: PByte; max: Byte; const length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509v3_asid_validate_path(v1: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509v3_addr_validate_path(v1: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NAMING_AUTHORITY_get0_authorityId(const n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl; external CLibCrypto;
function NAMING_AUTHORITY_get0_authorityURL(const n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl; external CLibCrypto;
function NAMING_AUTHORITY_get0_authorityText(const n: PNAMING_AUTHORITY): PASN1_STRING; cdecl; external CLibCrypto;
procedure NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl; external CLibCrypto;
procedure NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl; external CLibCrypto;
procedure NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl; external CLibCrypto;
function ADMISSION_SYNTAX_get0_admissionAuthority(const as_: ADMISSION_SYNTAX): PGENERAL_NAME; cdecl; external CLibCrypto;
procedure ADMISSION_SYNTAX_set0_admissionAuthority(as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl; external CLibCrypto;
function ADMISSIONS_get0_admissionAuthority(const a: PADMISSIONS): PGENERAL_NAME; cdecl; external CLibCrypto;
procedure ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME); cdecl; external CLibCrypto;
function ADMISSIONS_get0_namingAuthority(const a: PADMISSIONS): PNAMING_AUTHORITY; cdecl; external CLibCrypto;
procedure ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl; external CLibCrypto;
function PROFESSION_INFO_get0_addProfessionInfo(const pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
procedure PROFESSION_INFO_set0_addProfessionInfo(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl; external CLibCrypto;
function PROFESSION_INFO_get0_namingAuthority(const pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl; external CLibCrypto;
procedure PROFESSION_INFO_set0_namingAuthority(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl; external CLibCrypto;
function PROFESSION_INFO_get0_registrationNumber(const pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl; external CLibCrypto;
procedure PROFESSION_INFO_set0_registrationNumber(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl; external CLibCrypto;

{$ELSE}
var
  BASIC_CONSTRAINTS_free: procedure (bc : PBASIC_CONSTRAINTS); cdecl = nil;
  BASIC_CONSTRAINTS_new: function : PBASIC_CONSTRAINTS; cdecl = nil;
  AUTHORITY_KEYID_free: procedure (id : AUTHORITY_KEYID); cdecl = nil;
  AUTHORITY_KEYID_new: function : AUTHORITY_KEYID; cdecl = nil;
  GENERAL_NAME_free: procedure (a: PGENERAL_NAME); cdecl = nil;
  GENERAL_NAME_new: function : PGENERAL_NAME; cdecl = nil;
  GENERAL_NAME_cmp: function (a: PGENERAL_NAME; b: PGENERAL_NAME): TOpenSSL_C_INT; cdecl = nil;
  GENERAL_NAME_print: function (out_: PBIO; gen: PGENERAL_NAME): TOpenSSL_C_INT; cdecl = nil;
  GENERAL_NAMES_free: procedure (a: PGENERAL_NAMES); cdecl = nil;
  GENERAL_NAMES_new: function : PGENERAL_NAMES; cdecl = nil;
  OTHERNAME_cmp: function (a: POTHERNAME; b: POTHERNAME): TOpenSSL_C_INT; cdecl = nil;
  GENERAL_NAME_set0_value: procedure (a: PGENERAL_NAME; type_: TOpenSSL_C_INT; value: Pointer); cdecl = nil;
  GENERAL_NAME_get0_value: function (const a: PGENERAL_NAME; ptype: POpenSSL_C_INT): Pointer; cdecl = nil;
  GENERAL_NAME_set0_othername: function (gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  GENERAL_NAME_get0_otherName: function (const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  i2a_ACCESS_DESCRIPTION: function (bp: PBIO; const a: PACCESS_DESCRIPTION): TOpenSSL_C_INT; cdecl = nil;
  DIST_POINT_set_dpname: function (dpn: PDIST_POINT_NAME; iname: PX509_NAME): TOpenSSL_C_INT; cdecl = nil;
  NAME_CONSTRAINTS_check: function (x: PX509; nc: PNAME_CONSTRAINTS): TOpenSSL_C_INT; cdecl = nil;
  NAME_CONSTRAINTS_check_CN: function (x: PX509; nc: PNAME_CONSTRAINTS): TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_nconf_nid: function (conf: PCONF; ctx: PX509V3_CTX; ext_nid: TOpenSSL_C_INT; const value: PAnsiChar): PX509_EXTENSION; cdecl = nil;
  X509V3_EXT_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const name: PAnsiChar; const value: PAnsiChar): PX509_EXTENSION; cdecl = nil;
  X509V3_EXT_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_REQ_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; req: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_CRL_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_conf_nid: function (conf: Pointer; ctx: PX509V3_CTX; ext_nid: TOpenSSL_C_INT; const value: PAnsiChar): PX509_EXTENSION; cdecl = nil;
  X509V3_EXT_conf: function (conf: Pointer; ctx: PX509V3_CTX; const name: PAnsiChar; const value: PAnsiChar): PX509_EXTENSION; cdecl = nil;
  X509V3_EXT_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; cert: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_REQ_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; req: PX509_REQ): TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_CRL_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = nil;
  X509V3_set_nconf: procedure (ctx: PX509V3_CTX; conf: PCONF); cdecl = nil;
  X509V3_get_string: function (ctx: PX509V3_CTX; const name: PAnsiChar; const section: PAnsiChar): PAnsiChar; cdecl = nil;
  X509V3_string_free: procedure (ctx: PX509V3_CTX; str: PAnsiChar); cdecl = nil;
  X509V3_set_ctx: procedure (ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TOpenSSL_C_INT); cdecl = nil;
  X509V3_EXT_add_alias: function (nid_to: TOpenSSL_C_INT; nid_from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_cleanup: procedure ; cdecl = nil;
  X509V3_add_standard_extensions: function : TOpenSSL_C_INT; cdecl = nil;
  X509V3_EXT_d2i: function (ext: PX509_EXTENSION): Pointer; cdecl = nil;
  X509V3_EXT_i2d: function (ext_nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl = nil;
  X509V3_EXT_print: function (out_: PBIO; ext: PX509_EXTENSION; flag: TOpenSSL_C_ULONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_check_ca: function (x: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_check_purpose: function (x: PX509; id: TOpenSSL_C_INT; ca: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_supported_extension: function (ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl = nil;
  X509_PURPOSE_set: function (p: POpenSSL_C_INT; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_check_issued: function (issuer: PX509; subject: PX509): TOpenSSL_C_INT; cdecl = nil;
  X509_check_akid: function (issuer: PX509; akid: PAUTHORITY_KEYID): TOpenSSL_C_INT; cdecl = nil;
  X509_set_proxy_flag: procedure (x: PX509); cdecl = nil;
  X509_set_proxy_pathlen: procedure (x: PX509; l: TOpenSSL_C_LONG); cdecl = nil;
  X509_get_proxy_pathlen: function (x: PX509): TOpenSSL_C_LONG; cdecl = nil;
  X509_get_extension_flags: function (x: PX509): TOpenSSL_C_UINT32; cdecl = nil;
  X509_get_key_usage: function (x: PX509): TOpenSSL_C_UINT32; cdecl = nil;
  X509_get_extended_key_usage: function (x: PX509): TOpenSSL_C_UINT32; cdecl = nil;
  X509_get0_subject_key_id: function (x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  X509_get0_authority_key_id: function (x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  X509_get0_authority_serial: function (x: PX509): PASN1_INTEGER; cdecl = nil;
  X509_PURPOSE_get_count: function : TOpenSSL_C_INT; cdecl = nil;
  X509_PURPOSE_get0: function (idx: TOpenSSL_C_INT): PX509_PURPOSE; cdecl = nil;
  X509_PURPOSE_get_by_sname: function (const sname: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  X509_PURPOSE_get_by_id: function (id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509_PURPOSE_get0_name: function (const xp: PX509_PURPOSE): PAnsiChar; cdecl = nil;
  X509_PURPOSE_get0_sname: function (const xp: PX509_PURPOSE): PAnsiChar; cdecl = nil;
  X509_PURPOSE_get_trust: function (const xp: PX509_PURPOSE): TOpenSSL_C_INT; cdecl = nil;
  X509_PURPOSE_cleanup: procedure ; cdecl = nil;
  X509_PURPOSE_get_id: function (const v1: PX509_PURPOSE): TOpenSSL_C_INT; cdecl = nil;
  X509_get1_email: function (x: PX509): PSTACK_OF_OPENSSL_STRING; cdecl = nil;
  X509_REQ_get1_email: function ( x : PX509_REQ): PSTACK_OF_OPENSSL_STRING; cdecl = nil;
  X509_email_free: procedure (sk : PSTACK_OF_OPENSSL_STRING); cdecl = nil;
  X509_get1_ocsp: function (x: PX509): PSTACK_OF_OPENSSL_STRING; cdecl = nil;
  X509_check_host: function (x: PX509; const chk: PAnsiChar; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT; peername: PPAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  X509_check_email: function (x: PX509; const chk: PAnsiChar; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  X509_check_ip: function (x: PX509; const chk: PByte; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  X509_check_ip_asc: function (x: PX509; const ipasc: PAnsiChar; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  a2i_IPADDRESS: function (const ipasc: PAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  a2i_IPADDRESS_NC: function (const ipasc: PAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  X509_POLICY_NODE_print: procedure (out_: PBIO; node: PX509_POLICY_NODE; indent: TOpenSSL_C_INT); cdecl = nil;
  X509v3_addr_get_range: function (aor: PIPAddressOrRange; const afi: TOpenSSL_C_UINT; min: PByte; max: Byte; const length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  X509v3_asid_validate_path: function (v1: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = nil;
  X509v3_addr_validate_path: function (v1: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = nil;
  NAMING_AUTHORITY_get0_authorityId: function (const n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl = nil;
  NAMING_AUTHORITY_get0_authorityURL: function (const n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl = nil;
  NAMING_AUTHORITY_get0_authorityText: function (const n: PNAMING_AUTHORITY): PASN1_STRING; cdecl = nil;
  NAMING_AUTHORITY_set0_authorityId: procedure (n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl = nil;
  NAMING_AUTHORITY_set0_authorityURL: procedure (n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl = nil;
  NAMING_AUTHORITY_set0_authorityText: procedure (n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl = nil;
  ADMISSION_SYNTAX_get0_admissionAuthority: function (const as_: ADMISSION_SYNTAX): PGENERAL_NAME; cdecl = nil;
  ADMISSION_SYNTAX_set0_admissionAuthority: procedure (as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl = nil;
  ADMISSIONS_get0_admissionAuthority: function (const a: PADMISSIONS): PGENERAL_NAME; cdecl = nil;
  ADMISSIONS_set0_admissionAuthority: procedure (a: PADMISSIONS; aa: PGENERAL_NAME); cdecl = nil;
  ADMISSIONS_get0_namingAuthority: function (const a: PADMISSIONS): PNAMING_AUTHORITY; cdecl = nil;
  ADMISSIONS_set0_namingAuthority: procedure (a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl = nil;
  PROFESSION_INFO_get0_addProfessionInfo: function (const pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl = nil;
  PROFESSION_INFO_set0_addProfessionInfo: procedure (pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl = nil;
  PROFESSION_INFO_get0_namingAuthority: function (const pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl = nil;
  PROFESSION_INFO_set0_namingAuthority: procedure (pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl = nil;
  PROFESSION_INFO_get0_registrationNumber: function (const pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl = nil;
  PROFESSION_INFO_set0_registrationNumber: procedure (pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl = nil;
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
procedure ERROR_BASIC_CONSTRAINTS_free(bc : PBASIC_CONSTRAINTS); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BASIC_CONSTRAINTS_free');
end;

function ERROR_BASIC_CONSTRAINTS_new: PBASIC_CONSTRAINTS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BASIC_CONSTRAINTS_new');
end;

procedure ERROR_AUTHORITY_KEYID_free(id : AUTHORITY_KEYID); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AUTHORITY_KEYID_free');
end;

function ERROR_AUTHORITY_KEYID_new: AUTHORITY_KEYID; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AUTHORITY_KEYID_new');
end;

procedure ERROR_GENERAL_NAME_free(a: PGENERAL_NAME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_free');
end;

function ERROR_GENERAL_NAME_new: PGENERAL_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_new');
end;

function ERROR_GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_cmp');
end;

function ERROR_GENERAL_NAME_print(out_: PBIO; gen: PGENERAL_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_print');
end;

procedure ERROR_GENERAL_NAMES_free(a: PGENERAL_NAMES); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAMES_free');
end;

function ERROR_GENERAL_NAMES_new: PGENERAL_NAMES; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAMES_new');
end;

function ERROR_OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OTHERNAME_cmp');
end;

procedure ERROR_GENERAL_NAME_set0_value(a: PGENERAL_NAME; type_: TOpenSSL_C_INT; value: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_set0_value');
end;

function ERROR_GENERAL_NAME_get0_value(const a: PGENERAL_NAME; ptype: POpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_get0_value');
end;

function ERROR_GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_set0_othername');
end;

function ERROR_GENERAL_NAME_get0_otherName(const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('GENERAL_NAME_get0_otherName');
end;

function ERROR_i2a_ACCESS_DESCRIPTION(bp: PBIO; const a: PACCESS_DESCRIPTION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ACCESS_DESCRIPTION');
end;

function ERROR_DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DIST_POINT_set_dpname');
end;

function ERROR_NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAME_CONSTRAINTS_check');
end;

function ERROR_NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAME_CONSTRAINTS_check_CN');
end;

function ERROR_X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TOpenSSL_C_INT; const value: PAnsiChar): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_nconf_nid');
end;

function ERROR_X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; const name: PAnsiChar; const value: PAnsiChar): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_nconf');
end;

function ERROR_X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_add_nconf');
end;

function ERROR_X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_REQ_add_nconf');
end;

function ERROR_X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PAnsiChar; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_CRL_add_nconf');
end;

function ERROR_X509V3_EXT_conf_nid(conf: Pointer; ctx: PX509V3_CTX; ext_nid: TOpenSSL_C_INT; const value: PAnsiChar): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_conf_nid');
end;

function ERROR_X509V3_EXT_conf(conf: Pointer; ctx: PX509V3_CTX; const name: PAnsiChar; const value: PAnsiChar): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_conf');
end;

function ERROR_X509V3_EXT_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_add_conf');
end;

function ERROR_X509V3_EXT_REQ_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_REQ_add_conf');
end;

function ERROR_X509V3_EXT_CRL_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PAnsiChar; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_CRL_add_conf');
end;

procedure ERROR_X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_set_nconf');
end;

function ERROR_X509V3_get_string(ctx: PX509V3_CTX; const name: PAnsiChar; const section: PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_get_string');
end;

procedure ERROR_X509V3_string_free(ctx: PX509V3_CTX; str: PAnsiChar); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_string_free');
end;

procedure ERROR_X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_set_ctx');
end;

function ERROR_X509V3_EXT_add_alias(nid_to: TOpenSSL_C_INT; nid_from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_add_alias');
end;

procedure ERROR_X509V3_EXT_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_cleanup');
end;

function ERROR_X509V3_add_standard_extensions: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_add_standard_extensions');
end;

function ERROR_X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_d2i');
end;

function ERROR_X509V3_EXT_i2d(ext_nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_i2d');
end;

function ERROR_X509V3_EXT_print(out_: PBIO; ext: PX509_EXTENSION; flag: TOpenSSL_C_ULONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509V3_EXT_print');
end;

function ERROR_X509_check_ca(x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_ca');
end;

function ERROR_X509_check_purpose(x: PX509; id: TOpenSSL_C_INT; ca: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_purpose');
end;

function ERROR_X509_supported_extension(ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_supported_extension');
end;

function ERROR_X509_PURPOSE_set(p: POpenSSL_C_INT; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_set');
end;

function ERROR_X509_check_issued(issuer: PX509; subject: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_issued');
end;

function ERROR_X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_akid');
end;

procedure ERROR_X509_set_proxy_flag(x: PX509); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_proxy_flag');
end;

procedure ERROR_X509_set_proxy_pathlen(x: PX509; l: TOpenSSL_C_LONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_proxy_pathlen');
end;

function ERROR_X509_get_proxy_pathlen(x: PX509): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_proxy_pathlen');
end;

function ERROR_X509_get_extension_flags(x: PX509): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_extension_flags');
end;

function ERROR_X509_get_key_usage(x: PX509): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_key_usage');
end;

function ERROR_X509_get_extended_key_usage(x: PX509): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_extended_key_usage');
end;

function ERROR_X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_subject_key_id');
end;

function ERROR_X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_authority_key_id');
end;

function ERROR_X509_get0_authority_serial(x: PX509): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_authority_serial');
end;

function ERROR_X509_PURPOSE_get_count: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get_count');
end;

function ERROR_X509_PURPOSE_get0(idx: TOpenSSL_C_INT): PX509_PURPOSE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get0');
end;

function ERROR_X509_PURPOSE_get_by_sname(const sname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get_by_sname');
end;

function ERROR_X509_PURPOSE_get_by_id(id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get_by_id');
end;

function ERROR_X509_PURPOSE_get0_name(const xp: PX509_PURPOSE): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get0_name');
end;

function ERROR_X509_PURPOSE_get0_sname(const xp: PX509_PURPOSE): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get0_sname');
end;

function ERROR_X509_PURPOSE_get_trust(const xp: PX509_PURPOSE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get_trust');
end;

procedure ERROR_X509_PURPOSE_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_cleanup');
end;

function ERROR_X509_PURPOSE_get_id(const v1: PX509_PURPOSE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PURPOSE_get_id');
end;

function ERROR_X509_get1_email(x: PX509): PSTACK_OF_OPENSSL_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get1_email');
end;

function ERROR_X509_REQ_get1_email( x : PX509_REQ): PSTACK_OF_OPENSSL_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get1_email');
end;

procedure ERROR_X509_email_free(sk : PSTACK_OF_OPENSSL_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_email_free');
end;

function ERROR_X509_get1_ocsp(x: PX509): PSTACK_OF_OPENSSL_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get1_ocsp');
end;

function ERROR_X509_check_host(x: PX509; const chk: PAnsiChar; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT; peername: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_host');
end;

function ERROR_X509_check_email(x: PX509; const chk: PAnsiChar; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_email');
end;

function ERROR_X509_check_ip(x: PX509; const chk: PByte; chklen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_ip');
end;

function ERROR_X509_check_ip_asc(x: PX509; const ipasc: PAnsiChar; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_ip_asc');
end;

function ERROR_a2i_IPADDRESS(const ipasc: PAnsiChar): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_IPADDRESS');
end;

function ERROR_a2i_IPADDRESS_NC(const ipasc: PAnsiChar): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_IPADDRESS_NC');
end;

procedure ERROR_X509_POLICY_NODE_print(out_: PBIO; node: PX509_POLICY_NODE; indent: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509_POLICY_NODE_print');
end;

function ERROR_X509v3_addr_get_range(aor: PIPAddressOrRange; const afi: TOpenSSL_C_UINT; min: PByte; max: Byte; const length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509v3_addr_get_range');
end;

function ERROR_X509v3_asid_validate_path(v1: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509v3_asid_validate_path');
end;

function ERROR_X509v3_addr_validate_path(v1: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509v3_addr_validate_path');
end;

function ERROR_NAMING_AUTHORITY_get0_authorityId(const n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAMING_AUTHORITY_get0_authorityId');
end;

function ERROR_NAMING_AUTHORITY_get0_authorityURL(const n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAMING_AUTHORITY_get0_authorityURL');
end;

function ERROR_NAMING_AUTHORITY_get0_authorityText(const n: PNAMING_AUTHORITY): PASN1_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAMING_AUTHORITY_get0_authorityText');
end;

procedure ERROR_NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAMING_AUTHORITY_set0_authorityId');
end;

procedure ERROR_NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAMING_AUTHORITY_set0_authorityURL');
end;

procedure ERROR_NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NAMING_AUTHORITY_set0_authorityText');
end;

function ERROR_ADMISSION_SYNTAX_get0_admissionAuthority(const as_: ADMISSION_SYNTAX): PGENERAL_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ADMISSION_SYNTAX_get0_admissionAuthority');
end;

procedure ERROR_ADMISSION_SYNTAX_set0_admissionAuthority(as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ADMISSION_SYNTAX_set0_admissionAuthority');
end;

function ERROR_ADMISSIONS_get0_admissionAuthority(const a: PADMISSIONS): PGENERAL_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ADMISSIONS_get0_admissionAuthority');
end;

procedure ERROR_ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ADMISSIONS_set0_admissionAuthority');
end;

function ERROR_ADMISSIONS_get0_namingAuthority(const a: PADMISSIONS): PNAMING_AUTHORITY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ADMISSIONS_get0_namingAuthority');
end;

procedure ERROR_ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ADMISSIONS_set0_namingAuthority');
end;

function ERROR_PROFESSION_INFO_get0_addProfessionInfo(const pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PROFESSION_INFO_get0_addProfessionInfo');
end;

procedure ERROR_PROFESSION_INFO_set0_addProfessionInfo(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PROFESSION_INFO_set0_addProfessionInfo');
end;

function ERROR_PROFESSION_INFO_get0_namingAuthority(const pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PROFESSION_INFO_get0_namingAuthority');
end;

procedure ERROR_PROFESSION_INFO_set0_namingAuthority(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PROFESSION_INFO_set0_namingAuthority');
end;

function ERROR_PROFESSION_INFO_get0_registrationNumber(const pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PROFESSION_INFO_get0_registrationNumber');
end;

procedure ERROR_PROFESSION_INFO_set0_registrationNumber(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PROFESSION_INFO_set0_registrationNumber');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  BASIC_CONSTRAINTS_free := LoadLibCryptoFunction('BASIC_CONSTRAINTS_free');
  FuncLoadError := not assigned(BASIC_CONSTRAINTS_free);
  if FuncLoadError then
  begin
    BASIC_CONSTRAINTS_free :=  @ERROR_BASIC_CONSTRAINTS_free;
  end;

  BASIC_CONSTRAINTS_new := LoadLibCryptoFunction('BASIC_CONSTRAINTS_new');
  FuncLoadError := not assigned(BASIC_CONSTRAINTS_new);
  if FuncLoadError then
  begin
    BASIC_CONSTRAINTS_new :=  @ERROR_BASIC_CONSTRAINTS_new;
  end;

  AUTHORITY_KEYID_free := LoadLibCryptoFunction('AUTHORITY_KEYID_free');
  FuncLoadError := not assigned(AUTHORITY_KEYID_free);
  if FuncLoadError then
  begin
    AUTHORITY_KEYID_free :=  @ERROR_AUTHORITY_KEYID_free;
  end;

  AUTHORITY_KEYID_new := LoadLibCryptoFunction('AUTHORITY_KEYID_new');
  FuncLoadError := not assigned(AUTHORITY_KEYID_new);
  if FuncLoadError then
  begin
    AUTHORITY_KEYID_new :=  @ERROR_AUTHORITY_KEYID_new;
  end;

  GENERAL_NAME_free := LoadLibCryptoFunction('GENERAL_NAME_free');
  FuncLoadError := not assigned(GENERAL_NAME_free);
  if FuncLoadError then
  begin
    GENERAL_NAME_free :=  @ERROR_GENERAL_NAME_free;
  end;

  GENERAL_NAME_new := LoadLibCryptoFunction('GENERAL_NAME_new');
  FuncLoadError := not assigned(GENERAL_NAME_new);
  if FuncLoadError then
  begin
    GENERAL_NAME_new :=  @ERROR_GENERAL_NAME_new;
  end;

  GENERAL_NAME_cmp := LoadLibCryptoFunction('GENERAL_NAME_cmp');
  FuncLoadError := not assigned(GENERAL_NAME_cmp);
  if FuncLoadError then
  begin
    GENERAL_NAME_cmp :=  @ERROR_GENERAL_NAME_cmp;
  end;

  GENERAL_NAME_print := LoadLibCryptoFunction('GENERAL_NAME_print');
  FuncLoadError := not assigned(GENERAL_NAME_print);
  if FuncLoadError then
  begin
    GENERAL_NAME_print :=  @ERROR_GENERAL_NAME_print;
  end;

  GENERAL_NAMES_free := LoadLibCryptoFunction('GENERAL_NAMES_free');
  FuncLoadError := not assigned(GENERAL_NAMES_free);
  if FuncLoadError then
  begin
    GENERAL_NAMES_free :=  @ERROR_GENERAL_NAMES_free;
  end;

  GENERAL_NAMES_new := LoadLibCryptoFunction('GENERAL_NAMES_new');
  FuncLoadError := not assigned(GENERAL_NAMES_new);
  if FuncLoadError then
  begin
    GENERAL_NAMES_new :=  @ERROR_GENERAL_NAMES_new;
  end;

  OTHERNAME_cmp := LoadLibCryptoFunction('OTHERNAME_cmp');
  FuncLoadError := not assigned(OTHERNAME_cmp);
  if FuncLoadError then
  begin
    OTHERNAME_cmp :=  @ERROR_OTHERNAME_cmp;
  end;

  GENERAL_NAME_set0_value := LoadLibCryptoFunction('GENERAL_NAME_set0_value');
  FuncLoadError := not assigned(GENERAL_NAME_set0_value);
  if FuncLoadError then
  begin
    GENERAL_NAME_set0_value :=  @ERROR_GENERAL_NAME_set0_value;
  end;

  GENERAL_NAME_get0_value := LoadLibCryptoFunction('GENERAL_NAME_get0_value');
  FuncLoadError := not assigned(GENERAL_NAME_get0_value);
  if FuncLoadError then
  begin
    GENERAL_NAME_get0_value :=  @ERROR_GENERAL_NAME_get0_value;
  end;

  GENERAL_NAME_set0_othername := LoadLibCryptoFunction('GENERAL_NAME_set0_othername');
  FuncLoadError := not assigned(GENERAL_NAME_set0_othername);
  if FuncLoadError then
  begin
    GENERAL_NAME_set0_othername :=  @ERROR_GENERAL_NAME_set0_othername;
  end;

  GENERAL_NAME_get0_otherName := LoadLibCryptoFunction('GENERAL_NAME_get0_otherName');
  FuncLoadError := not assigned(GENERAL_NAME_get0_otherName);
  if FuncLoadError then
  begin
    GENERAL_NAME_get0_otherName :=  @ERROR_GENERAL_NAME_get0_otherName;
  end;

  i2a_ACCESS_DESCRIPTION := LoadLibCryptoFunction('i2a_ACCESS_DESCRIPTION');
  FuncLoadError := not assigned(i2a_ACCESS_DESCRIPTION);
  if FuncLoadError then
  begin
    i2a_ACCESS_DESCRIPTION :=  @ERROR_i2a_ACCESS_DESCRIPTION;
  end;

  DIST_POINT_set_dpname := LoadLibCryptoFunction('DIST_POINT_set_dpname');
  FuncLoadError := not assigned(DIST_POINT_set_dpname);
  if FuncLoadError then
  begin
    DIST_POINT_set_dpname :=  @ERROR_DIST_POINT_set_dpname;
  end;

  NAME_CONSTRAINTS_check := LoadLibCryptoFunction('NAME_CONSTRAINTS_check');
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check);
  if FuncLoadError then
  begin
    NAME_CONSTRAINTS_check :=  @ERROR_NAME_CONSTRAINTS_check;
  end;

  NAME_CONSTRAINTS_check_CN := LoadLibCryptoFunction('NAME_CONSTRAINTS_check_CN');
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check_CN);
  if FuncLoadError then
  begin
    NAME_CONSTRAINTS_check_CN :=  @ERROR_NAME_CONSTRAINTS_check_CN;
  end;

  X509V3_EXT_nconf_nid := LoadLibCryptoFunction('X509V3_EXT_nconf_nid');
  FuncLoadError := not assigned(X509V3_EXT_nconf_nid);
  if FuncLoadError then
  begin
    X509V3_EXT_nconf_nid :=  @ERROR_X509V3_EXT_nconf_nid;
  end;

  X509V3_EXT_nconf := LoadLibCryptoFunction('X509V3_EXT_nconf');
  FuncLoadError := not assigned(X509V3_EXT_nconf);
  if FuncLoadError then
  begin
    X509V3_EXT_nconf :=  @ERROR_X509V3_EXT_nconf;
  end;

  X509V3_EXT_add_nconf := LoadLibCryptoFunction('X509V3_EXT_add_nconf');
  FuncLoadError := not assigned(X509V3_EXT_add_nconf);
  if FuncLoadError then
  begin
    X509V3_EXT_add_nconf :=  @ERROR_X509V3_EXT_add_nconf;
  end;

  X509V3_EXT_REQ_add_nconf := LoadLibCryptoFunction('X509V3_EXT_REQ_add_nconf');
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_nconf);
  if FuncLoadError then
  begin
    X509V3_EXT_REQ_add_nconf :=  @ERROR_X509V3_EXT_REQ_add_nconf;
  end;

  X509V3_EXT_CRL_add_nconf := LoadLibCryptoFunction('X509V3_EXT_CRL_add_nconf');
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_nconf);
  if FuncLoadError then
  begin
    X509V3_EXT_CRL_add_nconf :=  @ERROR_X509V3_EXT_CRL_add_nconf;
  end;

  X509V3_EXT_conf_nid := LoadLibCryptoFunction('X509V3_EXT_conf_nid');
  FuncLoadError := not assigned(X509V3_EXT_conf_nid);
  if FuncLoadError then
  begin
    X509V3_EXT_conf_nid :=  @ERROR_X509V3_EXT_conf_nid;
  end;

  X509V3_EXT_conf := LoadLibCryptoFunction('X509V3_EXT_conf');
  FuncLoadError := not assigned(X509V3_EXT_conf);
  if FuncLoadError then
  begin
    X509V3_EXT_conf :=  @ERROR_X509V3_EXT_conf;
  end;

  X509V3_EXT_add_conf := LoadLibCryptoFunction('X509V3_EXT_add_conf');
  FuncLoadError := not assigned(X509V3_EXT_add_conf);
  if FuncLoadError then
  begin
    X509V3_EXT_add_conf :=  @ERROR_X509V3_EXT_add_conf;
  end;

  X509V3_EXT_REQ_add_conf := LoadLibCryptoFunction('X509V3_EXT_REQ_add_conf');
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_conf);
  if FuncLoadError then
  begin
    X509V3_EXT_REQ_add_conf :=  @ERROR_X509V3_EXT_REQ_add_conf;
  end;

  X509V3_EXT_CRL_add_conf := LoadLibCryptoFunction('X509V3_EXT_CRL_add_conf');
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_conf);
  if FuncLoadError then
  begin
    X509V3_EXT_CRL_add_conf :=  @ERROR_X509V3_EXT_CRL_add_conf;
  end;

  X509V3_set_nconf := LoadLibCryptoFunction('X509V3_set_nconf');
  FuncLoadError := not assigned(X509V3_set_nconf);
  if FuncLoadError then
  begin
    X509V3_set_nconf :=  @ERROR_X509V3_set_nconf;
  end;

  X509V3_get_string := LoadLibCryptoFunction('X509V3_get_string');
  FuncLoadError := not assigned(X509V3_get_string);
  if FuncLoadError then
  begin
    X509V3_get_string :=  @ERROR_X509V3_get_string;
  end;

  X509V3_string_free := LoadLibCryptoFunction('X509V3_string_free');
  FuncLoadError := not assigned(X509V3_string_free);
  if FuncLoadError then
  begin
    X509V3_string_free :=  @ERROR_X509V3_string_free;
  end;

  X509V3_set_ctx := LoadLibCryptoFunction('X509V3_set_ctx');
  FuncLoadError := not assigned(X509V3_set_ctx);
  if FuncLoadError then
  begin
    X509V3_set_ctx :=  @ERROR_X509V3_set_ctx;
  end;

  X509V3_EXT_add_alias := LoadLibCryptoFunction('X509V3_EXT_add_alias');
  FuncLoadError := not assigned(X509V3_EXT_add_alias);
  if FuncLoadError then
  begin
    X509V3_EXT_add_alias :=  @ERROR_X509V3_EXT_add_alias;
  end;

  X509V3_EXT_cleanup := LoadLibCryptoFunction('X509V3_EXT_cleanup');
  FuncLoadError := not assigned(X509V3_EXT_cleanup);
  if FuncLoadError then
  begin
    X509V3_EXT_cleanup :=  @ERROR_X509V3_EXT_cleanup;
  end;

  X509V3_add_standard_extensions := LoadLibCryptoFunction('X509V3_add_standard_extensions');
  FuncLoadError := not assigned(X509V3_add_standard_extensions);
  if FuncLoadError then
  begin
    X509V3_add_standard_extensions :=  @ERROR_X509V3_add_standard_extensions;
  end;

  X509V3_EXT_d2i := LoadLibCryptoFunction('X509V3_EXT_d2i');
  FuncLoadError := not assigned(X509V3_EXT_d2i);
  if FuncLoadError then
  begin
    X509V3_EXT_d2i :=  @ERROR_X509V3_EXT_d2i;
  end;

  X509V3_EXT_i2d := LoadLibCryptoFunction('X509V3_EXT_i2d');
  FuncLoadError := not assigned(X509V3_EXT_i2d);
  if FuncLoadError then
  begin
    X509V3_EXT_i2d :=  @ERROR_X509V3_EXT_i2d;
  end;

  X509V3_EXT_print := LoadLibCryptoFunction('X509V3_EXT_print');
  FuncLoadError := not assigned(X509V3_EXT_print);
  if FuncLoadError then
  begin
    X509V3_EXT_print :=  @ERROR_X509V3_EXT_print;
  end;

  X509_check_ca := LoadLibCryptoFunction('X509_check_ca');
  FuncLoadError := not assigned(X509_check_ca);
  if FuncLoadError then
  begin
    X509_check_ca :=  @ERROR_X509_check_ca;
  end;

  X509_check_purpose := LoadLibCryptoFunction('X509_check_purpose');
  FuncLoadError := not assigned(X509_check_purpose);
  if FuncLoadError then
  begin
    X509_check_purpose :=  @ERROR_X509_check_purpose;
  end;

  X509_supported_extension := LoadLibCryptoFunction('X509_supported_extension');
  FuncLoadError := not assigned(X509_supported_extension);
  if FuncLoadError then
  begin
    X509_supported_extension :=  @ERROR_X509_supported_extension;
  end;

  X509_PURPOSE_set := LoadLibCryptoFunction('X509_PURPOSE_set');
  FuncLoadError := not assigned(X509_PURPOSE_set);
  if FuncLoadError then
  begin
    X509_PURPOSE_set :=  @ERROR_X509_PURPOSE_set;
  end;

  X509_check_issued := LoadLibCryptoFunction('X509_check_issued');
  FuncLoadError := not assigned(X509_check_issued);
  if FuncLoadError then
  begin
    X509_check_issued :=  @ERROR_X509_check_issued;
  end;

  X509_check_akid := LoadLibCryptoFunction('X509_check_akid');
  FuncLoadError := not assigned(X509_check_akid);
  if FuncLoadError then
  begin
    X509_check_akid :=  @ERROR_X509_check_akid;
  end;

  X509_set_proxy_flag := LoadLibCryptoFunction('X509_set_proxy_flag');
  FuncLoadError := not assigned(X509_set_proxy_flag);
  if FuncLoadError then
  begin
    X509_set_proxy_flag :=  @ERROR_X509_set_proxy_flag;
  end;

  X509_set_proxy_pathlen := LoadLibCryptoFunction('X509_set_proxy_pathlen');
  FuncLoadError := not assigned(X509_set_proxy_pathlen);
  if FuncLoadError then
  begin
    X509_set_proxy_pathlen :=  @ERROR_X509_set_proxy_pathlen;
  end;

  X509_get_proxy_pathlen := LoadLibCryptoFunction('X509_get_proxy_pathlen');
  FuncLoadError := not assigned(X509_get_proxy_pathlen);
  if FuncLoadError then
  begin
    X509_get_proxy_pathlen :=  @ERROR_X509_get_proxy_pathlen;
  end;

  X509_get_extension_flags := LoadLibCryptoFunction('X509_get_extension_flags');
  FuncLoadError := not assigned(X509_get_extension_flags);
  if FuncLoadError then
  begin
    X509_get_extension_flags :=  @ERROR_X509_get_extension_flags;
  end;

  X509_get_key_usage := LoadLibCryptoFunction('X509_get_key_usage');
  FuncLoadError := not assigned(X509_get_key_usage);
  if FuncLoadError then
  begin
    X509_get_key_usage :=  @ERROR_X509_get_key_usage;
  end;

  X509_get_extended_key_usage := LoadLibCryptoFunction('X509_get_extended_key_usage');
  FuncLoadError := not assigned(X509_get_extended_key_usage);
  if FuncLoadError then
  begin
    X509_get_extended_key_usage :=  @ERROR_X509_get_extended_key_usage;
  end;

  X509_get0_subject_key_id := LoadLibCryptoFunction('X509_get0_subject_key_id');
  FuncLoadError := not assigned(X509_get0_subject_key_id);
  if FuncLoadError then
  begin
    X509_get0_subject_key_id :=  @ERROR_X509_get0_subject_key_id;
  end;

  X509_get0_authority_key_id := LoadLibCryptoFunction('X509_get0_authority_key_id');
  FuncLoadError := not assigned(X509_get0_authority_key_id);
  if FuncLoadError then
  begin
    X509_get0_authority_key_id :=  @ERROR_X509_get0_authority_key_id;
  end;

  X509_get0_authority_serial := LoadLibCryptoFunction('X509_get0_authority_serial');
  FuncLoadError := not assigned(X509_get0_authority_serial);
  if FuncLoadError then
  begin
    X509_get0_authority_serial :=  @ERROR_X509_get0_authority_serial;
  end;

  X509_PURPOSE_get_count := LoadLibCryptoFunction('X509_PURPOSE_get_count');
  FuncLoadError := not assigned(X509_PURPOSE_get_count);
  if FuncLoadError then
  begin
    X509_PURPOSE_get_count :=  @ERROR_X509_PURPOSE_get_count;
  end;

  X509_PURPOSE_get0 := LoadLibCryptoFunction('X509_PURPOSE_get0');
  FuncLoadError := not assigned(X509_PURPOSE_get0);
  if FuncLoadError then
  begin
    X509_PURPOSE_get0 :=  @ERROR_X509_PURPOSE_get0;
  end;

  X509_PURPOSE_get_by_sname := LoadLibCryptoFunction('X509_PURPOSE_get_by_sname');
  FuncLoadError := not assigned(X509_PURPOSE_get_by_sname);
  if FuncLoadError then
  begin
    X509_PURPOSE_get_by_sname :=  @ERROR_X509_PURPOSE_get_by_sname;
  end;

  X509_PURPOSE_get_by_id := LoadLibCryptoFunction('X509_PURPOSE_get_by_id');
  FuncLoadError := not assigned(X509_PURPOSE_get_by_id);
  if FuncLoadError then
  begin
    X509_PURPOSE_get_by_id :=  @ERROR_X509_PURPOSE_get_by_id;
  end;

  X509_PURPOSE_get0_name := LoadLibCryptoFunction('X509_PURPOSE_get0_name');
  FuncLoadError := not assigned(X509_PURPOSE_get0_name);
  if FuncLoadError then
  begin
    X509_PURPOSE_get0_name :=  @ERROR_X509_PURPOSE_get0_name;
  end;

  X509_PURPOSE_get0_sname := LoadLibCryptoFunction('X509_PURPOSE_get0_sname');
  FuncLoadError := not assigned(X509_PURPOSE_get0_sname);
  if FuncLoadError then
  begin
    X509_PURPOSE_get0_sname :=  @ERROR_X509_PURPOSE_get0_sname;
  end;

  X509_PURPOSE_get_trust := LoadLibCryptoFunction('X509_PURPOSE_get_trust');
  FuncLoadError := not assigned(X509_PURPOSE_get_trust);
  if FuncLoadError then
  begin
    X509_PURPOSE_get_trust :=  @ERROR_X509_PURPOSE_get_trust;
  end;

  X509_PURPOSE_cleanup := LoadLibCryptoFunction('X509_PURPOSE_cleanup');
  FuncLoadError := not assigned(X509_PURPOSE_cleanup);
  if FuncLoadError then
  begin
    X509_PURPOSE_cleanup :=  @ERROR_X509_PURPOSE_cleanup;
  end;

  X509_PURPOSE_get_id := LoadLibCryptoFunction('X509_PURPOSE_get_id');
  FuncLoadError := not assigned(X509_PURPOSE_get_id);
  if FuncLoadError then
  begin
    X509_PURPOSE_get_id :=  @ERROR_X509_PURPOSE_get_id;
  end;

  X509_get1_email := LoadLibCryptoFunction('X509_get1_email');
  FuncLoadError := not assigned(X509_get1_email);
  if FuncLoadError then
  begin
    X509_get1_email :=  @ERROR_X509_get1_email;
  end;

  X509_REQ_get1_email := LoadLibCryptoFunction('X509_REQ_get1_email');
  FuncLoadError := not assigned(X509_REQ_get1_email);
  if FuncLoadError then
  begin
    X509_REQ_get1_email :=  @ERROR_X509_REQ_get1_email;
  end;

  X509_email_free := LoadLibCryptoFunction('X509_email_free');
  FuncLoadError := not assigned(X509_email_free);
  if FuncLoadError then
  begin
    X509_email_free :=  @ERROR_X509_email_free;
  end;

  X509_get1_ocsp := LoadLibCryptoFunction('X509_get1_ocsp');
  FuncLoadError := not assigned(X509_get1_ocsp);
  if FuncLoadError then
  begin
    X509_get1_ocsp :=  @ERROR_X509_get1_ocsp;
  end;

  X509_check_host := LoadLibCryptoFunction('X509_check_host');
  FuncLoadError := not assigned(X509_check_host);
  if FuncLoadError then
  begin
    X509_check_host :=  @ERROR_X509_check_host;
  end;

  X509_check_email := LoadLibCryptoFunction('X509_check_email');
  FuncLoadError := not assigned(X509_check_email);
  if FuncLoadError then
  begin
    X509_check_email :=  @ERROR_X509_check_email;
  end;

  X509_check_ip := LoadLibCryptoFunction('X509_check_ip');
  FuncLoadError := not assigned(X509_check_ip);
  if FuncLoadError then
  begin
    X509_check_ip :=  @ERROR_X509_check_ip;
  end;

  X509_check_ip_asc := LoadLibCryptoFunction('X509_check_ip_asc');
  FuncLoadError := not assigned(X509_check_ip_asc);
  if FuncLoadError then
  begin
    X509_check_ip_asc :=  @ERROR_X509_check_ip_asc;
  end;

  a2i_IPADDRESS := LoadLibCryptoFunction('a2i_IPADDRESS');
  FuncLoadError := not assigned(a2i_IPADDRESS);
  if FuncLoadError then
  begin
    a2i_IPADDRESS :=  @ERROR_a2i_IPADDRESS;
  end;

  a2i_IPADDRESS_NC := LoadLibCryptoFunction('a2i_IPADDRESS_NC');
  FuncLoadError := not assigned(a2i_IPADDRESS_NC);
  if FuncLoadError then
  begin
    a2i_IPADDRESS_NC :=  @ERROR_a2i_IPADDRESS_NC;
  end;

  X509_POLICY_NODE_print := LoadLibCryptoFunction('X509_POLICY_NODE_print');
  FuncLoadError := not assigned(X509_POLICY_NODE_print);
  if FuncLoadError then
  begin
    X509_POLICY_NODE_print :=  @ERROR_X509_POLICY_NODE_print;
  end;

  X509v3_addr_get_range := LoadLibCryptoFunction('X509v3_addr_get_range');
  FuncLoadError := not assigned(X509v3_addr_get_range);
  if FuncLoadError then
  begin
    X509v3_addr_get_range :=  @ERROR_X509v3_addr_get_range;
  end;

  X509v3_asid_validate_path := LoadLibCryptoFunction('X509v3_asid_validate_path');
  FuncLoadError := not assigned(X509v3_asid_validate_path);
  if FuncLoadError then
  begin
    X509v3_asid_validate_path :=  @ERROR_X509v3_asid_validate_path;
  end;

  X509v3_addr_validate_path := LoadLibCryptoFunction('X509v3_addr_validate_path');
  FuncLoadError := not assigned(X509v3_addr_validate_path);
  if FuncLoadError then
  begin
    X509v3_addr_validate_path :=  @ERROR_X509v3_addr_validate_path;
  end;

  NAMING_AUTHORITY_get0_authorityId := LoadLibCryptoFunction('NAMING_AUTHORITY_get0_authorityId');
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityId);
  if FuncLoadError then
  begin
    NAMING_AUTHORITY_get0_authorityId :=  @ERROR_NAMING_AUTHORITY_get0_authorityId;
  end;

  NAMING_AUTHORITY_get0_authorityURL := LoadLibCryptoFunction('NAMING_AUTHORITY_get0_authorityURL');
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityURL);
  if FuncLoadError then
  begin
    NAMING_AUTHORITY_get0_authorityURL :=  @ERROR_NAMING_AUTHORITY_get0_authorityURL;
  end;

  NAMING_AUTHORITY_get0_authorityText := LoadLibCryptoFunction('NAMING_AUTHORITY_get0_authorityText');
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityText);
  if FuncLoadError then
  begin
    NAMING_AUTHORITY_get0_authorityText :=  @ERROR_NAMING_AUTHORITY_get0_authorityText;
  end;

  NAMING_AUTHORITY_set0_authorityId := LoadLibCryptoFunction('NAMING_AUTHORITY_set0_authorityId');
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityId);
  if FuncLoadError then
  begin
    NAMING_AUTHORITY_set0_authorityId :=  @ERROR_NAMING_AUTHORITY_set0_authorityId;
  end;

  NAMING_AUTHORITY_set0_authorityURL := LoadLibCryptoFunction('NAMING_AUTHORITY_set0_authorityURL');
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityURL);
  if FuncLoadError then
  begin
    NAMING_AUTHORITY_set0_authorityURL :=  @ERROR_NAMING_AUTHORITY_set0_authorityURL;
  end;

  NAMING_AUTHORITY_set0_authorityText := LoadLibCryptoFunction('NAMING_AUTHORITY_set0_authorityText');
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityText);
  if FuncLoadError then
  begin
    NAMING_AUTHORITY_set0_authorityText :=  @ERROR_NAMING_AUTHORITY_set0_authorityText;
  end;

  ADMISSION_SYNTAX_get0_admissionAuthority := LoadLibCryptoFunction('ADMISSION_SYNTAX_get0_admissionAuthority');
  FuncLoadError := not assigned(ADMISSION_SYNTAX_get0_admissionAuthority);
  if FuncLoadError then
  begin
    ADMISSION_SYNTAX_get0_admissionAuthority :=  @ERROR_ADMISSION_SYNTAX_get0_admissionAuthority;
  end;

  ADMISSION_SYNTAX_set0_admissionAuthority := LoadLibCryptoFunction('ADMISSION_SYNTAX_set0_admissionAuthority');
  FuncLoadError := not assigned(ADMISSION_SYNTAX_set0_admissionAuthority);
  if FuncLoadError then
  begin
    ADMISSION_SYNTAX_set0_admissionAuthority :=  @ERROR_ADMISSION_SYNTAX_set0_admissionAuthority;
  end;

  ADMISSIONS_get0_admissionAuthority := LoadLibCryptoFunction('ADMISSIONS_get0_admissionAuthority');
  FuncLoadError := not assigned(ADMISSIONS_get0_admissionAuthority);
  if FuncLoadError then
  begin
    ADMISSIONS_get0_admissionAuthority :=  @ERROR_ADMISSIONS_get0_admissionAuthority;
  end;

  ADMISSIONS_set0_admissionAuthority := LoadLibCryptoFunction('ADMISSIONS_set0_admissionAuthority');
  FuncLoadError := not assigned(ADMISSIONS_set0_admissionAuthority);
  if FuncLoadError then
  begin
    ADMISSIONS_set0_admissionAuthority :=  @ERROR_ADMISSIONS_set0_admissionAuthority;
  end;

  ADMISSIONS_get0_namingAuthority := LoadLibCryptoFunction('ADMISSIONS_get0_namingAuthority');
  FuncLoadError := not assigned(ADMISSIONS_get0_namingAuthority);
  if FuncLoadError then
  begin
    ADMISSIONS_get0_namingAuthority :=  @ERROR_ADMISSIONS_get0_namingAuthority;
  end;

  ADMISSIONS_set0_namingAuthority := LoadLibCryptoFunction('ADMISSIONS_set0_namingAuthority');
  FuncLoadError := not assigned(ADMISSIONS_set0_namingAuthority);
  if FuncLoadError then
  begin
    ADMISSIONS_set0_namingAuthority :=  @ERROR_ADMISSIONS_set0_namingAuthority;
  end;

  PROFESSION_INFO_get0_addProfessionInfo := LoadLibCryptoFunction('PROFESSION_INFO_get0_addProfessionInfo');
  FuncLoadError := not assigned(PROFESSION_INFO_get0_addProfessionInfo);
  if FuncLoadError then
  begin
    PROFESSION_INFO_get0_addProfessionInfo :=  @ERROR_PROFESSION_INFO_get0_addProfessionInfo;
  end;

  PROFESSION_INFO_set0_addProfessionInfo := LoadLibCryptoFunction('PROFESSION_INFO_set0_addProfessionInfo');
  FuncLoadError := not assigned(PROFESSION_INFO_set0_addProfessionInfo);
  if FuncLoadError then
  begin
    PROFESSION_INFO_set0_addProfessionInfo :=  @ERROR_PROFESSION_INFO_set0_addProfessionInfo;
  end;

  PROFESSION_INFO_get0_namingAuthority := LoadLibCryptoFunction('PROFESSION_INFO_get0_namingAuthority');
  FuncLoadError := not assigned(PROFESSION_INFO_get0_namingAuthority);
  if FuncLoadError then
  begin
    PROFESSION_INFO_get0_namingAuthority :=  @ERROR_PROFESSION_INFO_get0_namingAuthority;
  end;

  PROFESSION_INFO_set0_namingAuthority := LoadLibCryptoFunction('PROFESSION_INFO_set0_namingAuthority');
  FuncLoadError := not assigned(PROFESSION_INFO_set0_namingAuthority);
  if FuncLoadError then
  begin
    PROFESSION_INFO_set0_namingAuthority :=  @ERROR_PROFESSION_INFO_set0_namingAuthority;
  end;

  PROFESSION_INFO_get0_registrationNumber := LoadLibCryptoFunction('PROFESSION_INFO_get0_registrationNumber');
  FuncLoadError := not assigned(PROFESSION_INFO_get0_registrationNumber);
  if FuncLoadError then
  begin
    PROFESSION_INFO_get0_registrationNumber :=  @ERROR_PROFESSION_INFO_get0_registrationNumber;
  end;

  PROFESSION_INFO_set0_registrationNumber := LoadLibCryptoFunction('PROFESSION_INFO_set0_registrationNumber');
  FuncLoadError := not assigned(PROFESSION_INFO_set0_registrationNumber);
  if FuncLoadError then
  begin
    PROFESSION_INFO_set0_registrationNumber :=  @ERROR_PROFESSION_INFO_set0_registrationNumber;
  end;

end;

procedure UnLoad;
begin
  BASIC_CONSTRAINTS_free := nil;
  BASIC_CONSTRAINTS_new := nil;
  AUTHORITY_KEYID_free := nil;
  AUTHORITY_KEYID_new := nil;
  GENERAL_NAME_free := nil;
  GENERAL_NAME_new := nil;
  GENERAL_NAME_cmp := nil;
  GENERAL_NAME_print := nil;
  GENERAL_NAMES_free := nil;
  GENERAL_NAMES_new := nil;
  OTHERNAME_cmp := nil;
  GENERAL_NAME_set0_value := nil;
  GENERAL_NAME_get0_value := nil;
  GENERAL_NAME_set0_othername := nil;
  GENERAL_NAME_get0_otherName := nil;
  i2a_ACCESS_DESCRIPTION := nil;
  DIST_POINT_set_dpname := nil;
  NAME_CONSTRAINTS_check := nil;
  NAME_CONSTRAINTS_check_CN := nil;
  X509V3_EXT_nconf_nid := nil;
  X509V3_EXT_nconf := nil;
  X509V3_EXT_add_nconf := nil;
  X509V3_EXT_REQ_add_nconf := nil;
  X509V3_EXT_CRL_add_nconf := nil;
  X509V3_EXT_conf_nid := nil;
  X509V3_EXT_conf := nil;
  X509V3_EXT_add_conf := nil;
  X509V3_EXT_REQ_add_conf := nil;
  X509V3_EXT_CRL_add_conf := nil;
  X509V3_set_nconf := nil;
  X509V3_get_string := nil;
  X509V3_string_free := nil;
  X509V3_set_ctx := nil;
  X509V3_EXT_add_alias := nil;
  X509V3_EXT_cleanup := nil;
  X509V3_add_standard_extensions := nil;
  X509V3_EXT_d2i := nil;
  X509V3_EXT_i2d := nil;
  X509V3_EXT_print := nil;
  X509_check_ca := nil;
  X509_check_purpose := nil;
  X509_supported_extension := nil;
  X509_PURPOSE_set := nil;
  X509_check_issued := nil;
  X509_check_akid := nil;
  X509_set_proxy_flag := nil;
  X509_set_proxy_pathlen := nil;
  X509_get_proxy_pathlen := nil;
  X509_get_extension_flags := nil;
  X509_get_key_usage := nil;
  X509_get_extended_key_usage := nil;
  X509_get0_subject_key_id := nil;
  X509_get0_authority_key_id := nil;
  X509_get0_authority_serial := nil;
  X509_PURPOSE_get_count := nil;
  X509_PURPOSE_get0 := nil;
  X509_PURPOSE_get_by_sname := nil;
  X509_PURPOSE_get_by_id := nil;
  X509_PURPOSE_get0_name := nil;
  X509_PURPOSE_get0_sname := nil;
  X509_PURPOSE_get_trust := nil;
  X509_PURPOSE_cleanup := nil;
  X509_PURPOSE_get_id := nil;
  X509_get1_email := nil;
  X509_REQ_get1_email := nil;
  X509_email_free := nil;
  X509_get1_ocsp := nil;
  X509_check_host := nil;
  X509_check_email := nil;
  X509_check_ip := nil;
  X509_check_ip_asc := nil;
  a2i_IPADDRESS := nil;
  a2i_IPADDRESS_NC := nil;
  X509_POLICY_NODE_print := nil;
  X509v3_addr_get_range := nil;
  X509v3_asid_validate_path := nil;
  X509v3_addr_validate_path := nil;
  NAMING_AUTHORITY_get0_authorityId := nil;
  NAMING_AUTHORITY_get0_authorityURL := nil;
  NAMING_AUTHORITY_get0_authorityText := nil;
  NAMING_AUTHORITY_set0_authorityId := nil;
  NAMING_AUTHORITY_set0_authorityURL := nil;
  NAMING_AUTHORITY_set0_authorityText := nil;
  ADMISSION_SYNTAX_get0_admissionAuthority := nil;
  ADMISSION_SYNTAX_set0_admissionAuthority := nil;
  ADMISSIONS_get0_admissionAuthority := nil;
  ADMISSIONS_set0_admissionAuthority := nil;
  ADMISSIONS_get0_namingAuthority := nil;
  ADMISSIONS_set0_namingAuthority := nil;
  PROFESSION_INFO_get0_addProfessionInfo := nil;
  PROFESSION_INFO_set0_addProfessionInfo := nil;
  PROFESSION_INFO_get0_namingAuthority := nil;
  PROFESSION_INFO_set0_namingAuthority := nil;
  PROFESSION_INFO_get0_registrationNumber := nil;
  PROFESSION_INFO_set0_registrationNumber := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
