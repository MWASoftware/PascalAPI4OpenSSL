(* This unit was generated from the source file ssl.h2pas 
It should not be modified directly. All changes should be made to ssl.h2pas
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


unit OpenSSL_ssl;




interface

// Headers for OpenSSL 1.1.1
// ssl.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_async,
  OpenSSL_bio,
  OpenSSL_crypto,
  OpenSSL_pem,
  OpenSSL_tls1,
  OpenSSL_ssl3,
  OpenSSL_x509;

{$MINENUMSIZE 4}

const
  (* OpenSSL version number for ASN.1 encoding of the session information *)
  (*-
   * Version 0 - initial version
   * Version 1 - added the optional peer certificate
   *)
  SSL_SESSION_ASN1_VERSION = $0001;
  
  SSL_MAX_SSL_SESSION_ID_LENGTH = 32;
  SSL_MAX_SID_CTX_LENGTH = 32;

  SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES = 512/8;
  SSL_MAX_KEY_ARG_LENGTH = 8;
  SSL_MAX_MASTER_KEY_LENGTH = 48;

  (* The maximum number of encrypt/decrypt pipelines we can support *)
  SSL_MAX_PIPELINES = 32;

  (* text strings for the ciphers *)

  (* These are used to specify which ciphers to use and not to use *)

  SSL_TXT_LOW = AnsiString('LOW');
  SSL_TXT_MEDIUM = AnsiString('MEDIUM');
  SSL_TXT_HIGH = AnsiString('HIGH');
  SSL_TXT_FIPS = AnsiString('FIPS');

  SSL_TXT_aNULL = AnsiString('aNULL');
  SSL_TXT_eNULL = AnsiString('eNULL');
  SSL_TXT_NULL = AnsiString('NULL');

  SSL_TXT_kRSA = AnsiString('kRSA');
  SSL_TXT_kDHr = AnsiString('kDHr');
  SSL_TXT_kDHd = AnsiString('kDHd');
  SSL_TXT_kDH = AnsiString('kDH');
  SSL_TXT_kEDH = AnsiString('kEDH');
  SSL_TXT_kDHE = AnsiString('kDHE');
  SSL_TXT_kECDHr = AnsiString('kECDHr');
//const SSL_TXT_kECDHe = AnsiString('kECDHe');
  SSL_TXT_kECDH = AnsiString('kECDH');
  SSL_TXT_kEECDH = AnsiString('kEECDH');
  SSL_TXT_kECDHE = AnsiString('kECDHE');
  SSL_TXT_kPSK = AnsiString('kPSK');
  SSL_TXT_kRSAPSK = AnsiString('kRSAPSK');
  SSL_TXT_kECDHEPSK = AnsiString('kECDHEPSK');
  SSL_TXT_kDHEPSK = AnsiString('kDHEPSK');
  SSL_TXT_kGOST = AnsiString('kGOST');
  SSL_TXT_kSRP = AnsiString('kSRP');

  SSL_TXT_aRSA = AnsiString('aRSA');
  SSL_TXT_aDSS = AnsiString('aDSS');
  SSL_TXT_aDH = AnsiString('aDH');
  SSL_TXT_aECDH = AnsiString('aECDH');
  SSL_TXT_aECDSA = AnsiString('aECDSA');
  SSL_TXT_aPSK = AnsiString('aPSK');
  SSL_TXT_aGOST94 = AnsiString('aGOST94');
  SSL_TXT_aGOST01 = AnsiString('aGOST01');
  SSL_TXT_aGOST12 = AnsiString('aGOST12');
  SSL_TXT_aGOST = AnsiString('aGOST');
  SSL_TXT_aSRP = AnsiString('aSRP');

  SSL_TXT_DSS = AnsiString('DSS');
  SSL_TXT_DH = AnsiString('DH');
  SSL_TXT_DHE = AnsiString('DHE');
  SSL_TXT_EDH = AnsiString('EDH');
  //SSL_TXT_ADH = AnsiString('ADH');
  SSL_TXT_RSA = AnsiString('RSA');
  SSL_TXT_ECDH = AnsiString('ECDH');
  SSL_TXT_EECDH = AnsiString('EECDH');
  SSL_TXT_ECDHE = AnsiString('ECDHE');
  //SSL_TXT_AECDH = AnsiString('AECDH');
  SSL_TXT_ECDSA = AnsiString('ECDSA');
  SSL_TXT_PSK = AnsiString('PSK');
  SSL_TXT_SRP = AnsiString('SRP');

  SSL_TXT_DES = AnsiString('DES');
  SSL_TXT_3DES = AnsiString('3DES');
  SSL_TXT_RC4 = AnsiString('RC4');
  SSL_TXT_RC2 = AnsiString('RC2');
  SSL_TXT_IDEA = AnsiString('IDEA');
  SSL_TXT_SEED = AnsiString('SEED');
  SSL_TXT_AES128 = AnsiString('AES128');
  SSL_TXT_AES256 = AnsiString('AES256');
  SSL_TXT_AES = AnsiString('AES');
  SSL_TXT_AES_GCM = AnsiString('AESGCM');
  SSL_TXT_AES_CCM = AnsiString('AESCCM');
  SSL_TXT_AES_CCM_8 = AnsiString('AESCCM8');
  SSL_TXT_CAMELLIA128 = AnsiString('CAMELLIA128');
  SSL_TXT_CAMELLIA256 = AnsiString('CAMELLIA256');
  SSL_TXT_CAMELLIA = AnsiString('CAMELLIA');
  SSL_TXT_CHACHA20 = AnsiString('CHACHA20');
  SSL_TXT_GOST = AnsiString('GOST89');
  SSL_TXT_ARIA = AnsiString('ARIA');
  SSL_TXT_ARIA_GCM = AnsiString('ARIAGCM');
  SSL_TXT_ARIA128 = AnsiString('ARIA128');
  SSL_TXT_ARIA256 = AnsiString('ARIA256');

  SSL_TXT_MD5 = AnsiString('MD5');
  SSL_TXT_SHA1 = AnsiString('SHA1');
  SSL_TXT_SHA = AnsiString('SHA');
  SSL_TXT_GOST94 = AnsiString('GOST94');
  SSL_TXT_GOST89MAC = AnsiString('GOST89MAC');
  SSL_TXT_GOST12 = AnsiString('GOST12');
  SSL_TXT_GOST89MAC12 = AnsiString('GOST89MAC12');
  SSL_TXT_SHA256 = AnsiString('SHA256');
  SSL_TXT_SHA384 = AnsiString('SHA384');

  SSL_TXT_SSLV3 = AnsiString('SSLv3');
  SSL_TXT_TLSV1 = AnsiString('TLSv1');
  SSL_TXT_TLSV1_1 = AnsiString('TLSv1.1');
  SSL_TXT_TLSV1_2 = AnsiString('TLSv1.2');

  SSL_TXT_ALL = AnsiString('ALL');

  (*-
   * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
   * ciphers normally not being used.
   * Example: "RC4" will activate all ciphers using RC4 including ciphers
   * without authentication, which would normally disabled by DEFAULT (due
   * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
   * will make sure that it is also disabled in the specific selection.
   * COMPLEMENTOF* identifiers are portable between version, as adjustments
   * to the default cipher setup will also be included here.
   *
   * COMPLEMENTOFDEFAULT does not experience the same special treatment that
   * DEFAULT gets, as only selection is being done and no sorting as needed
   * for DEFAULT.
   *)
  SSL_TXT_CMPALL = AnsiString('COMPLEMENTOFALL');
  SSL_TXT_CMPDEF = AnsiString('COMPLEMENTOFDEFAULT');

  (*
   * The following cipher list is used by default. It also is substituted when
   * an application-defined cipher list string starts with 'DEFAULT'.
   * This applies to ciphersuites for TLSv1.2 and below.
   *)
  SSL_DEFAULT_CIPHER_LIST = AnsiString('ALL:!COMPLEMENTOFDEFAULT:!eNULL');
  (* This is the default set of TLSv1.3 ciphersuites *)
  TLS_DEFAULT_CIPHERSUITES = AnsiString('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256');

  (*
   * As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
   * starts with a reasonable order, and all we have to do for DEFAULT is
   * throwing out anonymous and unencrypted ciphersuites! (The latter are not
   * actually enabled by ALL, but "ALL:RSA" would enable some of them.)
   *)

  (* Used in SSL_set_shutdown()/SSL_get_shutdown(); *)
  SSL_SENT_SHUTDOWN = 1;
  SSL_RECEIVED_SHUTDOWN = 2;

  SSL_FILETYPE_ASN1 = X509_FILETYPE_ASN1;
  SSL_FILETYPE_PEM = X509_FILETYPE_PEM;

  {Error codes for the SSL functions.}
  SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = 220;

  (* Extension context codes *)
  (* This extension is only allowed in TLS *)
  SSL_EXT_TLS_ONLY = $0001;
  (* This extension is only allowed in DTLS *)
  SSL_EXT_DTLS_ONLY = $0002;
  (* Some extensions may be allowed in DTLS but we don't implement them for it *)
  SSL_EXT_TLS_IMPLEMENTATION_ONLY = $0004;
  (* Most extensions are not defined for SSLv3 but EXT_TYPE_renegotiate is *)
  SSL_EXT_SSL3_ALLOWED = $0008;
  (* Extension is only defined for TLS1.2 and below *)
  SSL_EXT_TLS1_2_AND_BELOW_ONLY = $0010;
  (* Extension is only defined for TLS1.3 and above *)
  SSL_EXT_TLS1_3_ONLY = $0020;
  (* Ignore this extension during parsing if we are resuming *)
  SSL_EXT_IGNORE_ON_RESUMPTION = $0040;
  SSL_EXT_CLIENT_HELLO = $0080;
  (* Really means TLS1.2 or below *)
  SSL_EXT_TLS1_2_SERVER_HELLO = $0100;
  SSL_EXT_TLS1_3_SERVER_HELLO = $0200;
  SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS = $0400;
  SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST = $0800;
  SSL_EXT_TLS1_3_CERTIFICATE = $1000;
  SSL_EXT_TLS1_3_NEW_SESSION_TICKET = $2000;
  SSL_EXT_TLS1_3_CERTIFICATE_REQUEST = $4000;

  (*
   * Some values are reserved until OpenSSL 1.2.0 because they were previously
   * included in SSL_OP_ALL in a 1.1.x release.
   *
   * Reserved value (until OpenSSL 1.2.0)                  $00000001U
   * Reserved value (until OpenSSL 1.2.0)                  $00000002U
   *)
  (* Allow initial connection to servers that don't support RI *)
  SSL_OP_LEGACY_SERVER_CONNECT = TOpenSSL_C_UINT($00000004);

  (* Reserved value (until OpenSSL 1.2.0)                  $00000008U *)
  SSL_OP_TLSEXT_PADDING =      TOpenSSL_C_UINT($00000010);
  (* Reserved value (until OpenSSL 1.2.0)                  $00000020U *)
  SSL_OP_SAFARI_ECDHE_ECDSA_BUG = TOpenSSL_C_UINT($00000040);
  (*
   * Reserved value (until OpenSSL 1.2.0)                  $00000080U
   * Reserved value (until OpenSSL 1.2.0)                  $00000100U
   * Reserved value (until OpenSSL 1.2.0)                  $00000200U
   *)

  (* In TLSv1.3 allow a non-(ec)dhe based kex_mode *)
  SSL_OP_ALLOW_NO_DHE_KEX                         = TOpenSSL_C_UINT($00000400);

  (*
   * Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added in
   * OpenSSL 0.9.6d.  Usually (depending on the application protocol) the
   * workaround is not needed.  Unfortunately some broken SSL/TLS
   * implementations cannot handle it at all, which is why we include it in
   * SSL_OP_ALL. Added in 0.9.6e
   *)
  SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS              = TOpenSSL_C_UINT($00000800);

  (* DTLS options *)
  SSL_OP_NO_QUERY_MTU                             = TOpenSSL_C_UINT($00001000);
  (* Turn on Cookie Exchange (on relevant for servers) *)
  SSL_OP_COOKIE_EXCHANGE                          = TOpenSSL_C_UINT($00002000);
  (* Don't use RFC4507 ticket extension *)
  SSL_OP_NO_TICKET                                = TOpenSSL_C_UINT($00004000);
  (* Use Cisco's "speshul" version of DTLS_BAD_VER
   * (only with deprecated DTLSv1_client_method())  *)
  SSL_OP_CISCO_ANYCONNECT                        = TOpenSSL_C_UINT($00008000);

  (* As server, disallow session resumption on renegotiation *)
  SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   = TOpenSSL_C_UINT($00010000);
  (* Don't use compression even if supported *)
  SSL_OP_NO_COMPRESSION                           = TOpenSSL_C_UINT($00020000);
  (* Permit unsafe legacy renegotiation *)
  SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        = TOpenSSL_C_UINT($00040000);
  (* Disable encrypt-then-mac *)
  SSL_OP_NO_ENCRYPT_THEN_MAC                      = TOpenSSL_C_UINT($00080000);

  (*
   * Enable TLSv1.3 Compatibility mode. This is on by default. A future version
   * of OpenSSL may have this disabled by default.
   *)
  SSL_OP_ENABLE_MIDDLEBOX_COMPAT                  = TOpenSSL_C_UINT($00100000);

  (* Prioritize Chacha20Poly1305 when client does.
   * Modifies SSL_OP_CIPHER_SERVER_PREFERENCE *)
  SSL_OP_PRIORITIZE_CHACHA                        = TOpenSSL_C_UINT($00200000);

  (*
   * Set on servers to choose the cipher according to the server's preferences
   *)
  SSL_OP_CIPHER_SERVER_PREFERENCE                 = TOpenSSL_C_UINT($00400000);
  (*
   * If set, a server will allow a client to issue a SSLv3.0 version number as
   * latest version supported in the premaster secret, even when TLSv1.0
   * (version 3.1) was announced in the client hello. Normally this is
   * forbidden to prevent version rollback attacks.
   *)
  SSL_OP_TLS_ROLLBACK_BUG                         = TOpenSSL_C_UINT($00800000);

  (*
   * Switches off automatic TLSv1.3 anti-replay protection for early data. This
   * is a server-side option only (no effect on the client).
   *)
  SSL_OP_NO_ANTI_REPLAY                           = TOpenSSL_C_UINT($01000000);

  SSL_OP_NO_SSLv3                                 = TOpenSSL_C_UINT($02000000);
  SSL_OP_NO_TLSv1                                 = TOpenSSL_C_UINT($04000000);
  SSL_OP_NO_TLSv1_2                               = TOpenSSL_C_UINT($08000000);
  SSL_OP_NO_TLSv1_1                               = TOpenSSL_C_UINT($10000000);
  SSL_OP_NO_TLSv1_3                               = TOpenSSL_C_UINT($20000000);

  SSL_OP_NO_DTLSv1                                = TOpenSSL_C_UINT($04000000);
  SSL_OP_NO_DTLSv1_2                              = TOpenSSL_C_UINT($08000000);

  SSL_OP_NO_SSL_MASK = SSL_OP_NO_SSLv3 or SSL_OP_NO_TLSv1 or SSL_OP_NO_TLSv1_1
    or SSL_OP_NO_TLSv1_2 or SSL_OP_NO_TLSv1_3;
  SSL_OP_NO_DTLS_MASK = SSL_OP_NO_DTLSv1 or SSL_OP_NO_DTLSv1_2;

  (* Disallow all renegotiation *)
  SSL_OP_NO_RENEGOTIATION                         = TOpenSSL_C_UINT($40000000);

  (*
   * Make server add server-hello extension from early version of cryptopro
   * draft, when GOST ciphersuite is negotiated. Required for interoperability
   * with CryptoPro CSP 3.x
   *)
  SSL_OP_CRYPTOPRO_TLSEXT_BUG                     = TOpenSSL_C_UINT($80000000);

  (*
   * SSL_OP_ALL: various bug workarounds that should be rather harmless.
   * This used to be $000FFFFFL before 0.9.7.
   * This used to be $80000BFFU before 1.1.1.
   *)
  SSL_OP_ALL = SSL_OP_CRYPTOPRO_TLSEXT_BUG or SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    or SSL_OP_LEGACY_SERVER_CONNECT or SSL_OP_TLSEXT_PADDING or SSL_OP_SAFARI_ECDHE_ECDSA_BUG;

  (* OBSOLETE OPTIONS: retained for compatibility *)

  (* Removed from OpenSSL 1.1.0. Was $00000001L *)
  (* Related to removed SSLv2. *)
  SSL_OP_MICROSOFT_SESS_ID_BUG                    = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000002L *)
  (* Related to removed SSLv2. *)
  SSL_OP_NETSCAPE_CHALLENGE_BUG                   = $0;
  (* Removed from OpenSSL 0.9.8q and 1.0.0c. Was $00000008L *)
  (* Dead forever, see CVE-2010-4180 *)
  SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         = $0;
  (* Removed from OpenSSL 1.0.1h and 1.0.2. Was $00000010L *)
  (* Refers to ancient SSLREF and SSLv2. *)
  SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG              = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000020 *)
  SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER               = $0;
  (* Removed from OpenSSL 0.9.7h and 0.9.8b. Was $00000040L *)
  SSL_OP_MSIE_SSLV2_RSA_PADDING                   = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000080 *)
  (* Ancient SSLeay version. *)
  SSL_OP_SSLEAY_080_CLIENT_DH_BUG                 = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000100L *)
  SSL_OP_TLS_D5_BUG                               = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000200L *)
  SSL_OP_TLS_BLOCK_PADDING_BUG                    = $0;
  (* Removed from OpenSSL 1.1.0. Was $00080000L *)
  SSL_OP_SINGLE_ECDH_USE                          = $0;
  (* Removed from OpenSSL 1.1.0. Was $00100000L *)
  SSL_OP_SINGLE_DH_USE                            = $0;
  (* Removed from OpenSSL 1.0.1k and 1.0.2. Was $00200000L *)
  SSL_OP_EPHEMERAL_RSA                            = $0;
  (* Removed from OpenSSL 1.1.0. Was $01000000L *)
  SSL_OP_NO_SSLv2                                 = $0;
  (* Removed from OpenSSL 1.0.1. Was $08000000L *)
  SSL_OP_PKCS1_CHECK_1                            = $0;
  (* Removed from OpenSSL 1.0.1. Was $10000000L *)
  SSL_OP_PKCS1_CHECK_2                            = $0;
  (* Removed from OpenSSL 1.1.0. Was $20000000L *)
  SSL_OP_NETSCAPE_CA_DN_BUG                       = $0;
  (* Removed from OpenSSL 1.1.0. Was $40000000L *)
  SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          = $0;

  (*
   * Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
   * when just a single record has been written):
   *)
  SSL_MODE_ENABLE_PARTIAL_WRITE = TOpenSSL_C_UINT($00000001);
  (*
   * Make it possible to retry SSL_write() with changed buffer location (buffer
   * contents must stay the same!); this is not the default to avoid the
   * misconception that non-blocking SSL_write() behaves like non-blocking
   * write():
   *)
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = TOpenSSL_C_UINT($00000002);
  (*
   * Never bother the application with retries if the transport is blocking:
   *)
  SSL_MODE_AUTO_RETRY = TOpenSSL_C_UINT($00000004);
  (* Don't attempt to automatically build certificate chain *)
  SSL_MODE_NO_AUTO_CHAIN = TOpenSSL_C_UINT($00000008);
  (*
   * Save RAM by releasing read and write buffers when they're empty. (SSL3 and
   * TLS only.) Released buffers are freed.
   *)
  SSL_MODE_RELEASE_BUFFERS = TOpenSSL_C_UINT($00000010);
  (*
   * Send the current time in the Random fields of the ClientHello and
   * ServerHello records for compatibility with hypothetical implementations
   * that require it.
   *)
  SSL_MODE_SEND_CLIENTHELLO_TIME = TOpenSSL_C_UINT($00000020);
  SSL_MODE_SEND_SERVERHELLO_TIME = TOpenSSL_C_UINT($00000040);
  (*
   * Send TLS_FALLBACK_SCSV in the ClientHello. To be set only by applications
   * that reconnect with a downgraded protocol version; see
   * draft-ietf-tls-downgrade-scsv-00 for details. DO NOT ENABLE THIS if your
   * application attempts a normal handshake. Only use this in explicit
   * fallback retries, following the guidance in
   * draft-ietf-tls-downgrade-scsv-00.
   *)
  SSL_MODE_SEND_FALLBACK_SCSV = TOpenSSL_C_UINT($00000080);
  (*
   * Support Asynchronous operation
   *)
  SSL_MODE_ASYNC = TOpenSSL_C_UINT($00000100);

  (*
   * When using DTLS/SCTP, include the terminating zero in the label
   * used for computing the endpoint-pair shared secret. Required for
   * interoperability with implementations having this bug like these
   * older version of OpenSSL:
   * - OpenSSL 1.0.0 series
   * - OpenSSL 1.0.1 series
   * - OpenSSL 1.0.2 series
   * - OpenSSL 1.1.0 series
   * - OpenSSL 1.1.1 and 1.1.1a
   *)
  SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG = TOpenSSL_C_UINT($00000400);

  (* Cert related flags *)
  (*
   * Many implementations ignore some aspects of the TLS standards such as
   * enforcing certificate chain algorithms. When this is set we enforce them.
   *)
  SSL_CERT_FLAG_TLS_STRICT = TOpenSSL_C_UINT($00000001);
  (* Suite B modes, takes same values as certificate verify flags *)
  SSL_CERT_FLAG_SUITEB_128_LOS_ONLY = $10000;
  (* Suite B 192 bit only mode *)
  SSL_CERT_FLAG_SUITEB_192_LOS = $20000;
  (* Suite B 128 bit mode allowing 192 bit algorithms *)
  SSL_CERT_FLAG_SUITEB_128_LOS = $30000;

  (* Perform all sorts of protocol violations for testing purposes *)
  SSL_CERT_FLAG_BROKEN_PROTOCOL = $10000000;

  (* Flags for building certificate chains *)
  (* Treat any existing certificates as untrusted CAs *)
  SSL_BUILD_CHAIN_FLAG_UNTRUSTED = $1;
  (* Don't include root CA in chain *)
  SSL_BUILD_CHAIN_FLAG_NO_ROOT = $2;
  (* Just check certificates already there *)
  SSL_BUILD_CHAIN_FLAG_CHECK = $4;
  (* Ignore verification errors *)
  SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR = $8;
  (* Clear verification errors from queue *)
  SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR = $10;

  (* Flags returned by SSL_check_chain *)
  (* Certificate can be used with this session *)
  CERT_PKEY_VALID = $1;
  (* Certificate can also be used for signing *)
  CERT_PKEY_SIGN = $2;
  (* EE certificate signing algorithm OK *)
  CERT_PKEY_EE_SIGNATURE = $10;
  (* CA signature algorithms OK *)
  CERT_PKEY_CA_SIGNATURE = $20;
  (* EE certificate parameters OK *)
  CERT_PKEY_EE_PARAM = $40;
  (* CA certificate parameters OK *)
  CERT_PKEY_CA_PARAM = $80;
  (* Signing explicitly allowed as opposed to SHA1 fallback *)
  CERT_PKEY_EXPLICIT_SIGN = $100;
  (* Client CA issuer names match (always set for server cert) *)
  CERT_PKEY_ISSUER_NAME = $200;
  (* Cert type matches client types (always set for server cert) *)
  CERT_PKEY_CERT_TYPE = $400;
  (* Cert chain suitable to Suite B *)
  CERT_PKEY_SUITEB = $800;

  SSL_CONF_FLAG_CMDLINE = $1;
  SSL_CONF_FLAG_FILE = $2;
  SSL_CONF_FLAG_CLIENT = $4;
  SSL_CONF_FLAG_SERVER = $8;
  SSL_CONF_FLAG_SHOW_ERRORS = $10;
  SSL_CONF_FLAG_CERTIFICATE = $20;
  SSL_CONF_FLAG_REQUIRE_PRIVATE = $40;
  (* Configuration value types *)
  SSL_CONF_TYPE_UNKNOWN = $0;
  SSL_CONF_TYPE_STRING = $1;
  SSL_CONF_TYPE_FILE = $2;
  SSL_CONF_TYPE_DIR = $3;
  SSL_CONF_TYPE_NONE = $4;

  (* Maximum length of the application-controlled segment of a a TLSv1.3 cookie *)
  SSL_COOKIE_LENGTH = 4096;

  (* 100k max cert list *)
  SSL_MAX_CERT_LIST_DEFAULT = 1024 * 100;
  SSL_SESSION_CACHE_MAX_SIZE_DEFAULT = 1024 * 20;

  SSL_SESS_CACHE_OFF = $0000;
  SSL_SESS_CACHE_CLIENT = $0001;
  SSL_SESS_CACHE_SERVER = $0002;
  SSL_SESS_CACHE_BOTH = (SSL_SESS_CACHE_CLIENT or SSL_SESS_CACHE_SERVER);
  SSL_SESS_CACHE_NO_AUTO_CLEAR = $0080;
  (* enough comments already ... see SSL_CTX_set_session_cache_mode(3) *)
  SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = $0100;
  SSL_SESS_CACHE_NO_INTERNAL_STORE = $0200;
  SSL_SESS_CACHE_NO_INTERNAL = (SSL_SESS_CACHE_NO_INTERNAL_LOOKUP or SSL_SESS_CACHE_NO_INTERNAL_STORE);

  OPENSSL_NPN_UNSUPPORTED = 0;
  OPENSSL_NPN_NEGOTIATED = 1;
  OPENSSL_NPN_NO_OVERLAP = 2;

  (*
   * the maximum length of the buffer given to callbacks containing the
   * resulting identity/psk
   *)
  PSK_MAX_IDENTITY_LEN = 128;
  PSK_MAX_PSK_LEN = 256;

  SSL_NOTHING = 1;
  SSL_WRITING = 2;
  SSL_READING = 3;
  SSL_X509_LOOKUP = 4;
  SSL_ASYNC_PAUSED = 5;
  SSL_ASYNC_NO_JOBS = 6;
  SSL_CLIENT_HELLO_CB = 7;

  SSL_MAC_FLAG_READ_MAC_STREAM = 1;
  SSL_MAC_FLAG_WRITE_MAC_STREAM = 2;

  (* TLSv1.3 KeyUpdate message types *)
  (* -1 used so that this is an invalid value for the on-the-wire protocol *)
  SSL_KEY_UPDATE_NONE = -1;
  (* Values as defined for the on-the-wire protocol *)
  SSL_KEY_UPDATE_NOT_REQUESTED = 0;
  SSL_KEY_UPDATE_REQUESTED = 1;

  (*
   * Most of the following state values are no longer used and are defined to be
   * the closest equivalent value in_ the current state machine code. Not all
   * defines have an equivalent and are set to a dummy value (-1). SSL_ST_CONNECT
   * and SSL_ST_ACCEPT are still in_ use in_ the definition of SSL_CB_ACCEPT_LOOP,
   * SSL_CB_ACCEPT_EXIT, SSL_CB_CONNECT_LOOP and SSL_CB_CONNECT_EXIT.
   *)
  SSL_ST_CONNECT = $1000;
  SSL_ST_ACCEPT = $2000;
  
  SSL_ST_MASK = $0FFF;
  
  SSL_CB_LOOP = $01;
  SSL_CB_EXIT = $02;
  SSL_CB_READ = $04;
  SSL_CB_WRITE = $08;
  SSL_CB_ALERT = $4000;
  SSL_CB_READ_ALERT = SSL_CB_ALERT or SSL_CB_READ;
  SSL_CB_WRITE_ALERT = SSL_CB_ALERT or SSL_CB_WRITE;
  SSL_CB_ACCEPT_LOOP = SSL_ST_ACCEPT or SSL_CB_LOOP;
  SSL_CB_ACCEPT_EXIT = SSL_ST_ACCEPT or SSL_CB_EXIT;
  SSL_CB_CONNECT_LOOP = SSL_ST_CONNECT or SSL_CB_LOOP;
  SSL_CB_CONNECT_EXIT = SSL_ST_CONNECT or SSL_CB_EXIT;
  SSL_CB_HANDSHAKE_START = $10;
  SSL_CB_HANDSHAKE_DONE = $20;

  (*
   * The following 3 states are kept in ssl->rlayer.rstate when reads fail, you
   * should not need these
   *)
  SSL_ST_READ_HEADER = $F0;
  SSL_ST_READ_BODY = $F1;
  SSL_ST_READ_DONE = $F2;

  (*
   * use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 3 options are
   * 'ored' with SSL_VERIFY_PEER if they are desired
   *)
  SSL_VERIFY_NONE = $00;
  SSL_VERIFY_PEER = $01;
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT = $02;
  SSL_VERIFY_CLIENT_ONCE = $04;
  SSL_VERIFY_POST_HANDSHAKE = $08;

  SSL_AD_REASON_OFFSET = 1000; (* offset to get SSL_R_... value
                                * from SSL_AD_... *)
  (* These alert types are for SSLv3 and TLSv1 *)
  SSL_AD_CLOSE_NOTIFY = SSL3_AD_CLOSE_NOTIFY;
  (* fatal *)
  SSL_AD_UNEXPECTED_MESSAGE = SSL3_AD_UNEXPECTED_MESSAGE;
  (* fatal *)
  SSL_AD_BAD_RECORD_MAC = SSL3_AD_BAD_RECORD_MAC;
  SSL_AD_DECRYPTION_FAILED = TLS1_AD_DECRYPTION_FAILED;
  SSL_AD_RECORD_OVERFLOW = TLS1_AD_RECORD_OVERFLOW;
  (* fatal *)
  SSL_AD_DECOMPRESSION_FAILURE = SSL3_AD_DECOMPRESSION_FAILURE;
  (* fatal *)
  SSL_AD_HANDSHAKE_FAILURE = SSL3_AD_HANDSHAKE_FAILURE;
  (* Not for TLS *)
  SSL_AD_NO_CERTIFICATE = SSL3_AD_NO_CERTIFICATE;
  SSL_AD_BAD_CERTIFICATE = SSL3_AD_BAD_CERTIFICATE;
  SSL_AD_UNSUPPORTED_CERTIFICATE = SSL3_AD_UNSUPPORTED_CERTIFICATE;
  SSL_AD_CERTIFICATE_REVOKED = SSL3_AD_CERTIFICATE_REVOKED;
  SSL_AD_CERTIFICATE_EXPIRED = SSL3_AD_CERTIFICATE_EXPIRED;
  SSL_AD_CERTIFICATE_UNKNOWN = SSL3_AD_CERTIFICATE_UNKNOWN;
  (* fatal *)
  SSL_AD_ILLEGAL_PARAMETER = SSL3_AD_ILLEGAL_PARAMETER;
  (* fatal *)
  SSL_AD_UNKNOWN_CA = TLS1_AD_UNKNOWN_CA;
  (* fatal *)
  SSL_AD_ACCESS_DENIED = TLS1_AD_ACCESS_DENIED;
  (* fatal *)
  SSL_AD_DECODE_ERROR = TLS1_AD_DECODE_ERROR;
  SSL_AD_DECRYPT_ERROR = TLS1_AD_DECRYPT_ERROR;
  (* fatal *)
  SSL_AD_EXPORT_RESTRICTION = TLS1_AD_EXPORT_RESTRICTION;
  (* fatal *)
  SSL_AD_PROTOCOL_VERSION = TLS1_AD_PROTOCOL_VERSION;
  (* fatal *)
  SSL_AD_INSUFFICIENT_SECURITY = TLS1_AD_INSUFFICIENT_SECURITY;
  (* fatal *)
  SSL_AD_INTERNAL_ERROR = TLS1_AD_INTERNAL_ERROR;
  SSL_AD_USER_CANCELLED = TLS1_AD_USER_CANCELLED;
  SSL_AD_NO_RENEGOTIATION = TLS1_AD_NO_RENEGOTIATION;
  SSL_AD_MISSING_EXTENSION = TLS13_AD_MISSING_EXTENSION;
  SSL_AD_CERTIFICATE_REQUIRED = TLS13_AD_CERTIFICATE_REQUIRED;
  SSL_AD_UNSUPPORTED_EXTENSION = TLS1_AD_UNSUPPORTED_EXTENSION;
  SSL_AD_CERTIFICATE_UNOBTAINABLE = TLS1_AD_CERTIFICATE_UNOBTAINABLE;
  SSL_AD_UNRECOGNIZED_NAME = TLS1_AD_UNRECOGNIZED_NAME;
  SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE = TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
  SSL_AD_BAD_CERTIFICATE_HASH_VALUE = TLS1_AD_BAD_CERTIFICATE_HASH_VALUE;
  (* fatal *)
  SSL_AD_UNKNOWN_PSK_IDENTITY = TLS1_AD_UNKNOWN_PSK_IDENTITY;
  (* fatal *)
  SSL_AD_INAPPROPRIATE_FALLBACK = TLS1_AD_INAPPROPRIATE_FALLBACK;
  SSL_AD_NO_APPLICATION_PROTOCOL = TLS1_AD_NO_APPLICATION_PROTOCOL;
  SSL_ERROR_NONE = 0;
  SSL_ERROR_SSL = 1;
  SSL_ERROR_WANT_READ = 2;
  SSL_ERROR_WANT_WRITE = 3;
  SSL_ERROR_WANT_X509_LOOKUP = 4;
  SSL_ERROR_SYSCALL = 5; (* look at error stack/return
                          * value/errno *)
  SSL_ERROR_ZERO_RETURN = 6;
  SSL_ERROR_WANT_CONNECT = 7;
  SSL_ERROR_WANT_ACCEPT = 8;
  SSL_ERROR_WANT_ASYNC = 9;
  SSL_ERROR_WANT_ASYNC_JOB = 10;
  SSL_ERROR_WANT_CLIENT_HELLO_CB = 11;
  SSL_CTRL_SET_TMP_DH = 3;
  SSL_CTRL_SET_TMP_ECDH = 4;
  SSL_CTRL_SET_TMP_DH_CB = 6;
  SSL_CTRL_GET_CLIENT_CERT_REQUEST = 9;
  SSL_CTRL_GET_NUM_RENEGOTIATIONS = 10;
  SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS = 11;
  SSL_CTRL_GET_TOTAL_RENEGOTIATIONS = 12;
  SSL_CTRL_GET_FLAGS = 13;
  SSL_CTRL_EXTRA_CHAIN_CERT = 14;
  SSL_CTRL_SET_MSG_CALLBACK = 15;
  SSL_CTRL_SET_MSG_CALLBACK_ARG = 16;
  (* only applies to datagram connections *)
  SSL_CTRL_SET_MTU = 17;
  (* Stats *)
  SSL_CTRL_SESS_NUMBER = 20;
  SSL_CTRL_SESS_CONNECT = 21;
  SSL_CTRL_SESS_CONNECT_GOOD = 22;
  SSL_CTRL_SESS_CONNECT_RENEGOTIATE = 23;
  SSL_CTRL_SESS_ACCEPT = 24;
  SSL_CTRL_SESS_ACCEPT_GOOD = 25;
  SSL_CTRL_SESS_ACCEPT_RENEGOTIATE = 26;
  SSL_CTRL_SESS_HIT = 27;
  SSL_CTRL_SESS_CB_HIT = 28;
  SSL_CTRL_SESS_MISSES = 29;
  SSL_CTRL_SESS_TIMEOUTS = 30;
  SSL_CTRL_SESS_CACHE_FULL = 31;
  SSL_CTRL_MODE = 33;
  SSL_CTRL_GET_READ_AHEAD = 40;
  SSL_CTRL_SET_READ_AHEAD = 41;
  SSL_CTRL_SET_SESS_CACHE_SIZE = 42;
  SSL_CTRL_GET_SESS_CACHE_SIZE = 43;
  SSL_CTRL_SET_SESS_CACHE_MODE = 44;
  SSL_CTRL_GET_SESS_CACHE_MODE = 45;
  SSL_CTRL_GET_MAX_CERT_LIST = 50;
  SSL_CTRL_SET_MAX_CERT_LIST = 51;
  SSL_CTRL_SET_MAX_SEND_FRAGMENT = 52;
  (* see tls1.h for macros based on these *)
  SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53;
  SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54;
  SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
  SSL_CTRL_SET_TLSEXT_DEBUG_CB = 56;
  SSL_CTRL_SET_TLSEXT_DEBUG_ARG = 57;
  SSL_CTRL_GET_TLSEXT_TICKET_KEYS = 58;
  SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = 63;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = 64;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS = 66;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS = 67;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS = 68;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS = 69;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = 71;
  SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB = 72;
  SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB = 75;
  SSL_CTRL_SET_SRP_VERIFY_PARAM_CB = 76;
  SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB = 77;
  SSL_CTRL_SET_SRP_ARG = 78;
  SSL_CTRL_SET_TLS_EXT_SRP_USERNAME = 79;
  SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH = 80;
  SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD = 81;
  SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT = 85;
  SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING = 86;
  SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS = 87;
  DTLS_CTRL_GET_TIMEOUT = 73;
  DTLS_CTRL_HANDLE_TIMEOUT = 74;
  SSL_CTRL_GET_RI_SUPPORT = 76;
  SSL_CTRL_CLEAR_MODE = 78;
  SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB = 79;
  SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82;
  SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83;
  SSL_CTRL_CHAIN = 88;
  SSL_CTRL_CHAIN_CERT = 89;
  SSL_CTRL_GET_GROUPS = 90;
  SSL_CTRL_SET_GROUPS = 91;
  SSL_CTRL_SET_GROUPS_LIST = 92;
  SSL_CTRL_GET_SHARED_GROUP = 93;
  SSL_CTRL_SET_SIGALGS = 97;
  SSL_CTRL_SET_SIGALGS_LIST = 98;
  SSL_CTRL_CERT_FLAGS = 99;
  SSL_CTRL_CLEAR_CERT_FLAGS = 100;
  SSL_CTRL_SET_CLIENT_SIGALGS = 101;
  SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102;
  SSL_CTRL_GET_CLIENT_CERT_TYPES = 103;
  SSL_CTRL_SET_CLIENT_CERT_TYPES = 104;
  SSL_CTRL_BUILD_CERT_CHAIN = 105;
  SSL_CTRL_SET_VERIFY_CERT_STORE = 106;
  SSL_CTRL_SET_CHAIN_CERT_STORE = 107;
  SSL_CTRL_GET_PEER_SIGNATURE_NID = 108;
  SSL_CTRL_GET_PEER_TMP_KEY = 109;
  SSL_CTRL_GET_RAW_CIPHERLIST = 110;
  SSL_CTRL_GET_EC_POINT_FORMATS = 111;
  SSL_CTRL_GET_CHAIN_CERTS = 115;
  SSL_CTRL_SELECT_CURRENT_CERT = 116;
  SSL_CTRL_SET_CURRENT_CERT = 117;
  SSL_CTRL_SET_DH_AUTO = 118;
  DTLS_CTRL_SET_LINK_MTU = 120;
  DTLS_CTRL_GET_LINK_MIN_MTU = 121;
  SSL_CTRL_GET_EXTMS_SUPPORT = 122;
  SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
  SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
  SSL_CTRL_SET_SPLIT_SEND_FRAGMENT = 125;
  SSL_CTRL_SET_MAX_PIPELINES = 126;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE = 127;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB = 128;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129;
  SSL_CTRL_GET_MIN_PROTO_VERSION = 130;
  SSL_CTRL_GET_MAX_PROTO_VERSION = 131;
  SSL_CTRL_GET_SIGNATURE_NID = 132;
  SSL_CTRL_GET_TMP_KEY = 133;
  SSL_CERT_SET_FIRST = 1;
  SSL_CERT_SET_NEXT = 2;
  SSL_CERT_SET_SERVER = 3;

  (*
   * The following symbol names are old and obsolete. They are kept
   * for compatibility reasons only and should not be used anymore.
   *)
  SSL_CTRL_GET_CURVES = SSL_CTRL_GET_GROUPS;
  SSL_CTRL_SET_CURVES = SSL_CTRL_SET_GROUPS;
  SSL_CTRL_SET_CURVES_LIST = SSL_CTRL_SET_GROUPS_LIST;
  SSL_CTRL_GET_SHARED_CURVE = SSL_CTRL_GET_SHARED_GROUP;
  
//  SSL_get1_curves = SSL_get1_groups;
//  SSL_CTX_set1_curves = SSL_CTX_set1_groups;
//  SSL_CTX_set1_curves_list = SSL_CTX_set1_groups_list;
//  SSL_set1_curves = SSL_set1_groups;
//  SSL_set1_curves_list = SSL_set1_groups_list;
//  SSL_get_shared_curve = SSL_get_shared_group;

  (* serverinfo file format versions *)
  SSL_SERVERINFOV1 = 1;
  SSL_SERVERINFOV2 = 2;

  SSL_CLIENT_HELLO_SUCCESS = 1;
  SSL_CLIENT_HELLO_ERROR = 0;
  SSL_CLIENT_HELLO_RETRY = -1;

  SSL_READ_EARLY_DATA_ERROR = 0;
  SSL_READ_EARLY_DATA_SUCCESS = 1;
  SSL_READ_EARLY_DATA_FINISH = 2;

  SSL_EARLY_DATA_NOT_SENT = 0;
  SSL_EARLY_DATA_REJECTED = 1;
  SSL_EARLY_DATA_ACCEPTED = 2;

  //SSLv23_method = TLS_method;
  //SSLv23_server_method = TLS_server_method;
  //SSLv23_client_method = TLS_client_method;

  (* What the 'other' parameter contains in_ security callback *)
  (* Mask for type *)
  SSL_SECOP_OTHER_TYPE = $ffff0000;
  SSL_SECOP_OTHER_NONE = 0;
  SSL_SECOP_OTHER_CIPHER = (1 shl 16);
  SSL_SECOP_OTHER_CURVE = (2 shl 16);
  SSL_SECOP_OTHER_DH = (3 shl 16);
  SSL_SECOP_OTHER_PKEY = (4 shl 16);
  SSL_SECOP_OTHER_SIGALG = (5 shl 16);
  SSL_SECOP_OTHER_CERT = (6 shl 16);

  (* Indicated operation refers to peer key or certificate *)
  SSL_SECOP_PEER = $1000;

  (* Values for "op" parameter in security callback *)

  (* Called to filter ciphers *)
  (* Ciphers client supports *)
  SSL_SECOP_CIPHER_SUPPORTED = 1 or SSL_SECOP_OTHER_CIPHER;
  (* Cipher shared by client/server *)
  SSL_SECOP_CIPHER_SHARED = 2 or SSL_SECOP_OTHER_CIPHER;
  (* Sanity check of cipher server selects *)
  SSL_SECOP_CIPHER_CHECK = 3 or SSL_SECOP_OTHER_CIPHER;
  (* Curves supported by client *)
  SSL_SECOP_CURVE_SUPPORTED = 4 or SSL_SECOP_OTHER_CURVE;
  (* Curves shared by client/server *)
  SSL_SECOP_CURVE_SHARED = 5 or SSL_SECOP_OTHER_CURVE;
  (* Sanity check of curve server selects *)
  SSL_SECOP_CURVE_CHECK = 6 or SSL_SECOP_OTHER_CURVE;
  (* Temporary DH key *)
  SSL_SECOP_TMP_DH = 7 or SSL_SECOP_OTHER_PKEY;
  (* SSL/TLS version *)
  SSL_SECOP_VERSION = 9 or SSL_SECOP_OTHER_NONE;
  (* Session tickets *)
  SSL_SECOP_TICKET = 10 or SSL_SECOP_OTHER_NONE;
  (* Supported signature algorithms sent to peer *)
  SSL_SECOP_SIGALG_SUPPORTED = 11 or SSL_SECOP_OTHER_SIGALG;
  (* Shared signature algorithm *)
  SSL_SECOP_SIGALG_SHARED = 12 or SSL_SECOP_OTHER_SIGALG;
  (* Sanity check signature algorithm allowed *)
  SSL_SECOP_SIGALG_CHECK = 13 or SSL_SECOP_OTHER_SIGALG;
  (* Used to get mask of supported public key signature algorithms *)
  SSL_SECOP_SIGALG_MASK = 14 or SSL_SECOP_OTHER_SIGALG;
  (* Use to see if compression is allowed *)
  SSL_SECOP_COMPRESSION = 15 or SSL_SECOP_OTHER_NONE;
  (* EE key in certificate *)
  SSL_SECOP_EE_KEY = 16 or SSL_SECOP_OTHER_CERT;
  (* CA key in certificate *)
  SSL_SECOP_CA_KEY = 17 or SSL_SECOP_OTHER_CERT;
  (* CA digest algorithm in certificate *)
  SSL_SECOP_CA_MD = 18 or SSL_SECOP_OTHER_CERT;
  (* Peer EE key in certificate *)
  SSL_SECOP_PEER_EE_KEY = SSL_SECOP_EE_KEY or SSL_SECOP_PEER;
  (* Peer CA key in certificate *)
  SSL_SECOP_PEER_CA_KEY = SSL_SECOP_CA_KEY or SSL_SECOP_PEER;
  (* Peer CA digest algorithm in certificate *)
  SSL_SECOP_PEER_CA_MD = SSL_SECOP_CA_MD or SSL_SECOP_PEER;

  (* OPENSSL_INIT flag 0x010000 reserved for internal use *)
  OPENSSL_INIT_NO_LOAD_SSL_STRINGS = TOpenSSL_C_LONG($00100000);
  OPENSSL_INIT_LOAD_SSL_STRINGS = TOpenSSL_C_LONG($00200000);
  OPENSSL_INIT_SSL_DEFAULT = OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS;

  (* Support for ticket appdata *)
  (* fatal error, malloc failure *)
  SSL_TICKET_FATAL_ERR_MALLOC = 0;
  (* fatal error, either from parsing or decrypting the ticket *)
  SSL_TICKET_FATAL_ERR_OTHER = 1;
  (* No ticket present *)
  SSL_TICKET_NONE = 2;
  (* Empty ticket present *)
  SSL_TICKET_EMPTY = 3;
  (* the ticket couldn't be decrypted *)
  SSL_TICKET_NO_DECRYPT = 4;
  (* a ticket was successfully decrypted *)
  SSL_TICKET_SUCCESS = 5;
  (* same as above but the ticket needs to be renewed *)
  SSL_TICKET_SUCCESS_RENEW = 6;

  (* An error occurred *)
  SSL_TICKET_RETURN_ABORT = 0;
  (* Do not use the ticket, do not send a renewed ticket to the client *)
  SSL_TICKET_RETURN_IGNORE = 1;
  (* Do not use the ticket, send a renewed ticket to the client *)
  SSL_TICKET_RETURN_IGNORE_RENEW = 2;
  (* Use the ticket, do not send a renewed ticket to the client *)
  SSL_TICKET_RETURN_USE = 3;
  (* Use the ticket, send a renewed ticket to the client *)
  SSL_TICKET_RETURN_USE_RENEW = 4;

type
  (*
   * This is needed to stop compilers complaining about the 'struct ssl_st *'
   * function parameters used to prototype callbacks in SSL_CTX.
   *)
  ssl_crock_st = ^ssl_st;
  TLS_SESSION_TICKET_EXT = tls_session_ticket_ext_st;
  ssl_method_st = type Pointer;
  SSL_METHOD = ssl_method_st;
  PSSL_METHOD = ^SSL_METHOD;
  ssl_session_st = type Pointer;
  SSL_CIPHER = ssl_session_st;
  PSSL_CIPHER = ^SSL_CIPHER;
  SSL_SESSION = ssl_session_st;
  PSSL_SESSION = ^SSL_SESSION;
  PPSSL_SESSION = ^PSSL_SESSION;
  tls_sigalgs_st = type Pointer;
  TLS_SIGALGS = tls_sigalgs_st;
  ssl_conf_ctx_st = type Pointer;
  SSL_CONF_CTX = ssl_conf_ctx_st;
  PSSL_CONF_CTX = ^SSL_CONF_CTX;
  ssl_comp_st = type Pointer;
  SSL_COMP = ssl_comp_st;


  //STACK_OF(SSL_CIPHER);
  //STACK_OF(SSL_COMP);

  (* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*)
  srtp_protection_profile_st = record
    name: PAnsiChar;
    id: TOpenSSL_C_ULONG;
  end;
  SRTP_PROTECTION_PROFILE = srtp_protection_profile_st;
  PSRTP_PROTECTION_PROFILE = ^SRTP_PROTECTION_PROFILE;

  //DEFINE_STACK_OF(SRTP_PROTECTION_PROFILE)

  (* Typedefs for handling custom extensions *)
  custom_ext_add_cb = function (s: PSSL; ext_type: TOpenSSL_C_UINT; const out_: PByte; outlen: POpenSSL_C_SIZET; al: POpenSSL_C_INT; add_arg: Pointer): TOpenSSL_C_INT; cdecl;
  custom_ext_free_cb = procedure (s: PSSL; ext_type: TOpenSSL_C_UINT; const out_: PByte; add_arg: Pointer); cdecl;
  custom_ext_parse_cb = function (s: PSSL; ext_type: TOpenSSL_C_UINT; const in_: PByte; inlen: TOpenSSL_C_SIZET; al: POpenSSL_C_INT; parse_arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_custom_ext_add_cb_ex = function (s: PSSL; ext_type: TOpenSSL_C_UINT; context: TOpenSSL_C_UINT; const out_: PByte; outlen: POpenSSL_C_SIZET; x: Px509; chainidx: TOpenSSL_C_SIZET; al: POpenSSL_C_INT; add_arg: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_custom_ext_free_cb_ex = procedure (s: PSSL; ext_type: TOpenSSL_C_UINT; context: TOpenSSL_C_UINT; const out_: PByte; add_arg: Pointer); cdecl;
  SSL_custom_ext_parse_cb_ex = function (s: PSSL; ext_type: TOpenSSL_C_UINT; context: TOpenSSL_C_UINT; const in_: PByte; inlen: TOpenSSL_C_SIZET; x: Px509; chainidx: TOpenSSL_C_SIZET; al: POpenSSL_C_INT; parse_arg: Pointer): TOpenSSL_C_INT; cdecl;

  (* Typedef for verification callback *)
  SSL_verify_cb = function (preverify_ok: TOpenSSL_C_INT; x509_ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;

  tls_session_ticket_ext_cb_fn = function (s: PSSL; const data: PByte; len: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;

  (*
   * This callback type is used inside SSL_CTX, SSL, and in_ the functions that
   * set them. It is used to override the generation of SSL/TLS session IDs in_
   * a server. Return value should be zero on an error, non-zero to proceed.
   * Also, callbacks should themselves check if the id they generate is unique
   * otherwise the SSL handshake will fail with an error - callbacks can do
   * this using the 'ssl' value they're passed by;
   * SSL_has_matching_session_id(ssl, id, *id_len) The length value passed in_
   * is set at the maximum size the session ID can be. in_ SSLv3/TLSv1 it is 32
   * bytes. The callback can alter this length to be less if desired. It is
   * also an error for the callback to set the size to zero.
   *)
  GEN_SESSION_CB = function (ssl: PSSL; id: PByte; id_len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

  SSL_CTX_info_callback = procedure (const ssl: PSSL; type_: TOpenSSL_C_INT; val: TOpenSSL_C_INT); cdecl;
  SSL_CTX_client_cert_cb = function (ssl: PSSL; x509: PPx509; pkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;

  SSL_CTX_cookie_verify_cb = function (ssl: PSSL; cookie: PByte; cookie_len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb = function (ssl: PSSL; const cookie: PByte; cookie_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb = function (ssl: PSSL; cookie: PByte; cookie_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb = function (ssl: PSSL; const cookie: PByte; cookie_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

  SSL_CTX_alpn_select_cb_func = function (ssl: PSSL; const out_: PPByte; outlen: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT; arg: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_psk_client_cb_func = function (ssl: PSSL; const hint: PAnsiChar; identity: PAnsiChar; max_identity_len: TOpenSSL_C_UINT; psk: PByte; max_psk_len: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
  SSL_psk_server_cb_func = function (ssl: PSSL; const identity: PAnsiChar; psk: PByte; max_psk_len: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
  SSL_psk_find_session_cb_func = function (ssl: PSSL; const identity: PByte; identity_len: TOpenSSL_C_SIZET; sess: PPSSL_SESSION): TOpenSSL_C_INT; cdecl;
  SSL_psk_use_session_cb_func = function (ssl: PSSL; const md: PEVP_MD; const id: PPByte; idlen: POpenSSL_C_SIZET; sess: PPSSL_SESSION): TOpenSSL_C_INT; cdecl;

  (*
   * A callback for logging out TLS key material. This callback should log out
   * |line| followed by a newline.
   *)
  SSL_CTX_keylog_cb_func = procedure(const ssl: PSSL; const line: PAnsiChar); cdecl;

  (*
   * The valid handshake states (one for each type message sent and one for each
   * type of message received). There are also two "special" states:
   * TLS = TLS or DTLS state
   * DTLS = DTLS specific state
   * CR/SR = Client Read/Server Read
   * CW/SW = Client Write/Server Write
   *
   * The "special" states are:
   * TLS_ST_BEFORE = No handshake has been initiated yet
   * TLS_ST_OK = A handshake has been successfully completed
   *)
  TLS_ST_OK = (
    DTLS_ST_CR_HELLO_VERIFY_REQUEST,
    TLS_ST_CR_SRVR_HELLO,
    TLS_ST_CR_CERT,
    TLS_ST_CR_CERT_STATUS,
    TLS_ST_CR_KEY_EXCH,
    TLS_ST_CR_CERT_REQ,
    TLS_ST_CR_SRVR_DONE,
    TLS_ST_CR_SESSION_TICKET,
    TLS_ST_CR_CHANGE,
    TLS_ST_CR_FINISHED,
    TLS_ST_CW_CLNT_HELLO,
    TLS_ST_CW_CERT,
    TLS_ST_CW_KEY_EXCH,
    TLS_ST_CW_CERT_VRFY,
    TLS_ST_CW_CHANGE,
    TLS_ST_CW_NEXT_PROTO,
    TLS_ST_CW_FINISHED,
    TLS_ST_SW_HELLO_REQ,
    TLS_ST_SR_CLNT_HELLO,
    DTLS_ST_SW_HELLO_VERIFY_REQUEST,
    TLS_ST_SW_SRVR_HELLO,
    TLS_ST_SW_CERT,
    TLS_ST_SW_KEY_EXCH,
    TLS_ST_SW_CERT_REQ,
    TLS_ST_SW_SRVR_DONE,
    TLS_ST_SR_CERT,
    TLS_ST_SR_KEY_EXCH,
    TLS_ST_SR_CERT_VRFY,
    TLS_ST_SR_NEXT_PROTO,
    TLS_ST_SR_CHANGE,
    TLS_ST_SR_FINISHED,
    TLS_ST_SW_SESSION_TICKET,
    TLS_ST_SW_CERT_STATUS,
    TLS_ST_SW_CHANGE,
    TLS_ST_SW_FINISHED,
    TLS_ST_SW_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_CERT_VRFY,
    TLS_ST_SW_CERT_VRFY,
    TLS_ST_CR_HELLO_REQ,
    TLS_ST_SW_KEY_UPDATE,
    TLS_ST_CW_KEY_UPDATE,
    TLS_ST_SR_KEY_UPDATE,
    TLS_ST_CR_KEY_UPDATE,
    TLS_ST_EARLY_DATA,
    TLS_ST_PENDING_EARLY_DATA_END,
    TLS_ST_CW_END_OF_EARLY_DATA
  );
  OSSL_HANDSHAKE_STATE = TLS_ST_OK;

  SSL_CTX_set_cert_verify_callback_cb = function (v1: PX509_STORE_CTX; v2: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_cert_cb_cb = function (ssl: PSSL; arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_CTX_set_srp_client_pwd_callback_cb = function (v1: PSSL; v2: Pointer): PAnsiChar; cdecl;
  SSL_CTX_set_srp_verify_param_callback_cb = function (v1: PSSL; v2: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_srp_username_callback_cb = function (v1: PSSL; v2: POpenSSL_C_INT; v3: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_client_hello_cb_fn = function (s: PSSL; al: POpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_callback_ctrl_v3 = procedure; cdecl;
  SSL_CTX_callback_ctrl_v3 = procedure; cdecl;
  SSL_info_callback = procedure (const ssl: PSSL; type_: TOpenSSL_C_INT; val: TOpenSSL_C_INT); cdecl;

  (* NB: the |keylength| is only applicable when is_export is true *)
  SSL_CTX_set_tmp_dh_callback_dh = function (ssl: PSSL; is_export: TOpenSSL_C_INT; keylength: TOpenSSL_C_INT): PDH; cdecl;
  SSL_set_tmp_dh_callback_dh = function (ssl: PSSL; is_export: TOpenSSL_C_INT; keylength: TOpenSSL_C_INT): PDH; cdecl;
  SSL_CTX_set_not_resumable_session_callback_cb = function (ssl: PSSL; is_forward_secure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  SSL_set_not_resumable_session_callback_cb = function (ssl: PSSL; is_forward_secure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_record_padding_callback_cb = function (ssl: PSSL; type_: TOpenSSL_C_INT; len: TOpenSSL_C_SIZET; arg: Pointer): TOpenSSL_C_SIZET; cdecl;
  SSL_set_record_padding_callback_cb = function (ssl: PSSL; type_: TOpenSSL_C_INT; len: TOpenSSL_C_SIZET; arg: Pointer): TOpenSSL_C_SIZET; cdecl;
  
  (*
   * The validation type enumerates the available behaviours of the built-in SSL
   * CT validation callback selected via SSL_enable_ct() and SSL_CTX_enable_ct().
   * The underlying callback is a static function in libssl.
   *)
  SSL_CT_VALIDATION = (         
    SSL_CT_VALIDATION_PERMISSIVE = 0,
    SSL_CT_VALIDATION_STRICT
  );
  SSL_security_callback = function (const s: PSSL; const ctx: PSSL_CTX; op: TOpenSSL_C_INT; bits: TOpenSSL_C_INT; nid: TOpenSSL_C_INT; other: Pointer; ex: Pointer): TOpenSSL_C_INT; cdecl;

  (* Status codes passed to the decrypt session ticket callback. Some of these
   * are for internal use only and are never passed to the callback. *)
  SSL_TICKET_STATUS = TOpenSSL_C_INT;
  SSL_TICKET_RETURN = TOpenSSL_C_INT;

  SSL_CTX_generate_session_ticket_fn = function(s: PSSL; arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_CTX_decrypt_session_ticket_fn = function (s: PSSL; ss: PSSL_SESSION; const keyname: PByte; keyname_length: TOpenSSL_C_SIZET; status: SSL_TICKET_STATUS; arg: Pointer): SSL_TICKET_RETURN; cdecl;

  DTLS_timer_cb = function(s: PSSL; timer_us: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
  SSL_allow_early_data_cb_fn = function(s: PSSL; arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_CTX_sess_new_cb = function (ssl: PSSL; sess: PSSL_SESSION): TOpenSSL_C_INT; cdecl;

  SSL_CTX_sess_remove_cb = procedure(ctx: PSSL_CTX; sess: PSSL_SESSION); cdecl;

  TSSL_CTX_set_verify_callback = function (ok : TOpenSSL_C_INT; ctx : PX509_STORE_CTX) : TOpenSSL_C_INT; cdecl;



type
  TOpenSSL_Version = (sslUnknown,sslvSSLv2, sslvSSLv23, sslvSSLv3, sslvTLSv1,sslvTLSv1_1,
                      sslvTLSv1_2, sslvTLSv1_3);

  procedure OpenSSL_SetMethod(aMethod: TOpenSSL_Version); {used for pre 1.1.0 OpenSSL}

  function IsOpenSSL_SSLv2_Available : Boolean;
  function IsOpenSSL_SSLv3_Available : Boolean;
  function IsOpenSSL_SSLv23_Available : Boolean;
  function IsOpenSSL_TLSv1_0_Available : Boolean;
  function IsOpenSSL_TLSv1_1_Available : Boolean;
  function IsOpenSSL_TLSv1_2_Available : Boolean;
  function HasTLS_method: boolean;
  function SSL_CTX_set_min_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_CTX_set_max_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_CTX_get_min_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
  function SSL_CTX_get_max_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
  function SSL_set_min_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_set_max_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_get_min_proto_version(s: PSSL): TOpenSSL_C_LONG;
  function SSL_get_max_proto_version(s: PSSL): TOpenSSL_C_LONG;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM SSL_CTX_get_options}
{$EXTERNALSYM SSL_get_options}
{$EXTERNALSYM SSL_CTX_clear_options}
{$EXTERNALSYM SSL_clear_options}
{$EXTERNALSYM SSL_CTX_set_options}
{$EXTERNALSYM SSL_set_options}
{$EXTERNALSYM SSL_CTX_sess_set_new_cb}
{$EXTERNALSYM SSL_CTX_sess_get_new_cb}
{$EXTERNALSYM SSL_CTX_sess_set_remove_cb}
{$EXTERNALSYM SSL_CTX_sess_get_remove_cb}
{$EXTERNALSYM SSL_CTX_set_info_callback}
{$EXTERNALSYM SSL_CTX_get_info_callback}
{$EXTERNALSYM SSL_CTX_set_client_cert_cb}
{$EXTERNALSYM SSL_CTX_get_client_cert_cb}
{$EXTERNALSYM SSL_CTX_set_client_cert_engine}
{$EXTERNALSYM SSL_CTX_set_cookie_generate_cb}
{$EXTERNALSYM SSL_CTX_set_cookie_verify_cb}
{$EXTERNALSYM SSL_CTX_set_stateless_cookie_generate_cb}
{$EXTERNALSYM SSL_CTX_set_stateless_cookie_verify_cb}
{$EXTERNALSYM SSL_CTX_set_alpn_select_cb}
{$EXTERNALSYM SSL_get0_alpn_selected}
{$EXTERNALSYM SSL_CTX_set_psk_client_callback}
{$EXTERNALSYM SSL_set_psk_client_callback}
{$EXTERNALSYM SSL_CTX_set_psk_server_callback}
{$EXTERNALSYM SSL_set_psk_server_callback}
{$EXTERNALSYM SSL_set_psk_find_session_callback}
{$EXTERNALSYM SSL_CTX_set_psk_find_session_callback}
{$EXTERNALSYM SSL_set_psk_use_session_callback}
{$EXTERNALSYM SSL_CTX_set_psk_use_session_callback}
{$EXTERNALSYM SSL_CTX_set_keylog_callback}
{$EXTERNALSYM SSL_CTX_get_keylog_callback}
{$EXTERNALSYM SSL_CTX_set_max_early_data}
{$EXTERNALSYM SSL_CTX_get_max_early_data}
{$EXTERNALSYM SSL_set_max_early_data}
{$EXTERNALSYM SSL_get_max_early_data}
{$EXTERNALSYM SSL_CTX_set_recv_max_early_data}
{$EXTERNALSYM SSL_CTX_get_recv_max_early_data}
{$EXTERNALSYM SSL_set_recv_max_early_data}
{$EXTERNALSYM SSL_get_recv_max_early_data}
{$EXTERNALSYM SSL_in_init}
{$EXTERNALSYM SSL_in_before}
{$EXTERNALSYM SSL_is_init_finished}
{$EXTERNALSYM SSL_get_finished}
{$EXTERNALSYM SSL_get_peer_finished}
{$EXTERNALSYM BIO_f_ssl}
{$EXTERNALSYM BIO_new_ssl}
{$EXTERNALSYM BIO_new_ssl_connect}
{$EXTERNALSYM BIO_new_buffer_ssl_connect}
{$EXTERNALSYM BIO_ssl_copy_session_id}
{$EXTERNALSYM SSL_CTX_set_cipher_list}
{$EXTERNALSYM SSL_CTX_new}
{$EXTERNALSYM SSL_CTX_set_timeout}
{$EXTERNALSYM SSL_CTX_get_timeout}
{$EXTERNALSYM SSL_CTX_get_cert_store}
{$EXTERNALSYM SSL_want}
{$EXTERNALSYM SSL_clear}
{$EXTERNALSYM BIO_ssl_shutdown}
{$EXTERNALSYM SSL_CTX_up_ref}
{$EXTERNALSYM SSL_CTX_free}
{$EXTERNALSYM SSL_CTX_set_cert_store}
{$EXTERNALSYM SSL_CTX_set1_cert_store}
{$EXTERNALSYM SSL_CTX_flush_sessions}
{$EXTERNALSYM SSL_get_current_cipher}
{$EXTERNALSYM SSL_get_pending_cipher}
{$EXTERNALSYM SSL_CIPHER_get_bits}
{$EXTERNALSYM SSL_CIPHER_get_version}
{$EXTERNALSYM SSL_CIPHER_get_name}
{$EXTERNALSYM SSL_CIPHER_standard_name}
{$EXTERNALSYM OPENSSL_cipher_name}
{$EXTERNALSYM SSL_CIPHER_get_id}
{$EXTERNALSYM SSL_CIPHER_get_protocol_id}
{$EXTERNALSYM SSL_CIPHER_get_kx_nid}
{$EXTERNALSYM SSL_CIPHER_get_auth_nid}
{$EXTERNALSYM SSL_CIPHER_get_handshake_digest}
{$EXTERNALSYM SSL_CIPHER_is_aead}
{$EXTERNALSYM SSL_get_fd}
{$EXTERNALSYM SSL_get_rfd}
{$EXTERNALSYM SSL_get_wfd}
{$EXTERNALSYM SSL_get_cipher_list}
{$EXTERNALSYM SSL_get_shared_ciphers}
{$EXTERNALSYM SSL_get_read_ahead}
{$EXTERNALSYM SSL_pending}
{$EXTERNALSYM SSL_has_pending}
{$EXTERNALSYM SSL_set_fd}
{$EXTERNALSYM SSL_set_rfd}
{$EXTERNALSYM SSL_set_wfd}
{$EXTERNALSYM SSL_set0_rbio}
{$EXTERNALSYM SSL_set0_wbio}
{$EXTERNALSYM SSL_set_bio}
{$EXTERNALSYM SSL_get_rbio}
{$EXTERNALSYM SSL_get_wbio}
{$EXTERNALSYM SSL_set_cipher_list}
{$EXTERNALSYM SSL_CTX_set_ciphersuites}
{$EXTERNALSYM SSL_set_ciphersuites}
{$EXTERNALSYM SSL_get_verify_mode}
{$EXTERNALSYM SSL_get_verify_depth}
{$EXTERNALSYM SSL_get_verify_callback}
{$EXTERNALSYM SSL_set_read_ahead}
{$EXTERNALSYM SSL_set_verify}
{$EXTERNALSYM SSL_set_verify_depth}
{$EXTERNALSYM SSL_use_RSAPrivateKey}
{$EXTERNALSYM SSL_use_RSAPrivateKey_ASN1}
{$EXTERNALSYM SSL_use_PrivateKey}
{$EXTERNALSYM SSL_use_PrivateKey_ASN1}
{$EXTERNALSYM SSL_use_certificate}
{$EXTERNALSYM SSL_use_certificate_ASN1}
{$EXTERNALSYM SSL_CTX_use_serverinfo}
{$EXTERNALSYM SSL_CTX_use_serverinfo_ex}
{$EXTERNALSYM SSL_CTX_use_serverinfo_file}
{$EXTERNALSYM SSL_use_RSAPrivateKey_file}
{$EXTERNALSYM SSL_use_PrivateKey_file}
{$EXTERNALSYM SSL_use_certificate_file}
{$EXTERNALSYM SSL_CTX_use_RSAPrivateKey_file}
{$EXTERNALSYM SSL_CTX_use_PrivateKey_file}
{$EXTERNALSYM SSL_CTX_use_certificate_file}
{$EXTERNALSYM SSL_CTX_use_certificate_chain_file}
{$EXTERNALSYM SSL_use_certificate_chain_file}
{$EXTERNALSYM SSL_load_client_CA_file}
{$EXTERNALSYM SSL_add_file_cert_subjects_to_stack}
{$EXTERNALSYM SSL_add_dir_cert_subjects_to_stack}
{$EXTERNALSYM SSL_state_string}
{$EXTERNALSYM SSL_rstate_string}
{$EXTERNALSYM SSL_state_string_long}
{$EXTERNALSYM SSL_rstate_string_long}
{$EXTERNALSYM SSL_SESSION_get_time}
{$EXTERNALSYM SSL_SESSION_set_time}
{$EXTERNALSYM SSL_SESSION_get_timeout}
{$EXTERNALSYM SSL_SESSION_set_timeout}
{$EXTERNALSYM SSL_SESSION_get_protocol_version}
{$EXTERNALSYM SSL_SESSION_set_protocol_version}
{$EXTERNALSYM SSL_SESSION_get0_hostname}
{$EXTERNALSYM SSL_SESSION_set1_hostname}
{$EXTERNALSYM SSL_SESSION_get0_alpn_selected}
{$EXTERNALSYM SSL_SESSION_set1_alpn_selected}
{$EXTERNALSYM SSL_SESSION_get0_cipher}
{$EXTERNALSYM SSL_SESSION_set_cipher}
{$EXTERNALSYM SSL_SESSION_has_ticket}
{$EXTERNALSYM SSL_SESSION_get_ticket_lifetime_hint}
{$EXTERNALSYM SSL_SESSION_get0_ticket}
{$EXTERNALSYM SSL_SESSION_get_max_early_data}
{$EXTERNALSYM SSL_SESSION_set_max_early_data}
{$EXTERNALSYM SSL_copy_session_id}
{$EXTERNALSYM SSL_SESSION_get0_peer}
{$EXTERNALSYM SSL_SESSION_set1_id_context}
{$EXTERNALSYM SSL_SESSION_set1_id}
{$EXTERNALSYM SSL_SESSION_is_resumable}
{$EXTERNALSYM SSL_SESSION_new}
{$EXTERNALSYM SSL_SESSION_dup}
{$EXTERNALSYM SSL_SESSION_get_id}
{$EXTERNALSYM SSL_SESSION_get0_id_context}
{$EXTERNALSYM SSL_SESSION_get_compress_id}
{$EXTERNALSYM SSL_SESSION_print}
{$EXTERNALSYM SSL_SESSION_print_keylog}
{$EXTERNALSYM SSL_SESSION_up_ref}
{$EXTERNALSYM SSL_SESSION_free}
{$EXTERNALSYM SSL_set_session}
{$EXTERNALSYM SSL_CTX_add_session}
{$EXTERNALSYM SSL_CTX_remove_session}
{$EXTERNALSYM SSL_CTX_set_generate_session_id}
{$EXTERNALSYM SSL_set_generate_session_id}
{$EXTERNALSYM SSL_has_matching_session_id}
{$EXTERNALSYM d2i_SSL_SESSION}
{$EXTERNALSYM SSL_CTX_get_verify_mode}
{$EXTERNALSYM SSL_CTX_get_verify_depth}
{$EXTERNALSYM SSL_CTX_get_verify_callback}
{$EXTERNALSYM SSL_CTX_set_verify}
{$EXTERNALSYM SSL_CTX_set_verify_depth}
{$EXTERNALSYM SSL_CTX_set_cert_verify_callback}
{$EXTERNALSYM SSL_CTX_set_cert_cb}
{$EXTERNALSYM SSL_CTX_use_RSAPrivateKey}
{$EXTERNALSYM SSL_CTX_use_RSAPrivateKey_ASN1}
{$EXTERNALSYM SSL_CTX_use_PrivateKey}
{$EXTERNALSYM SSL_CTX_use_PrivateKey_ASN1}
{$EXTERNALSYM SSL_CTX_use_certificate}
{$EXTERNALSYM SSL_CTX_use_certificate_ASN1}
{$EXTERNALSYM SSL_CTX_set_default_passwd_cb}
{$EXTERNALSYM SSL_CTX_set_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_CTX_get_default_passwd_cb}
{$EXTERNALSYM SSL_CTX_get_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_set_default_passwd_cb}
{$EXTERNALSYM SSL_set_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_get_default_passwd_cb}
{$EXTERNALSYM SSL_get_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_CTX_check_private_key}
{$EXTERNALSYM SSL_check_private_key}
{$EXTERNALSYM SSL_CTX_set_session_id_context}
{$EXTERNALSYM SSL_new}
{$EXTERNALSYM SSL_up_ref}
{$EXTERNALSYM SSL_is_dtls}
{$EXTERNALSYM SSL_set_session_id_context}
{$EXTERNALSYM SSL_CTX_set_purpose}
{$EXTERNALSYM SSL_set_purpose}
{$EXTERNALSYM SSL_CTX_set_trust}
{$EXTERNALSYM SSL_set_trust}
{$EXTERNALSYM SSL_set1_host}
{$EXTERNALSYM SSL_add1_host}
{$EXTERNALSYM SSL_get0_peername}
{$EXTERNALSYM SSL_set_hostflags}
{$EXTERNALSYM SSL_CTX_dane_enable}
{$EXTERNALSYM SSL_CTX_dane_mtype_set}
{$EXTERNALSYM SSL_dane_enable}
{$EXTERNALSYM SSL_dane_tlsa_add}
{$EXTERNALSYM SSL_get0_dane_authority}
{$EXTERNALSYM SSL_get0_dane_tlsa}
{$EXTERNALSYM SSL_get0_dane}
{$EXTERNALSYM SSL_CTX_dane_set_flags}
{$EXTERNALSYM SSL_CTX_dane_clear_flags}
{$EXTERNALSYM SSL_dane_set_flags}
{$EXTERNALSYM SSL_dane_clear_flags}
{$EXTERNALSYM SSL_CTX_set1_param}
{$EXTERNALSYM SSL_set1_param}
{$EXTERNALSYM SSL_CTX_get0_param}
{$EXTERNALSYM SSL_get0_param}
{$EXTERNALSYM SSL_CTX_set_srp_username}
{$EXTERNALSYM SSL_CTX_set_srp_password}
{$EXTERNALSYM SSL_CTX_set_srp_strength}
{$EXTERNALSYM SSL_CTX_set_srp_client_pwd_callback}
{$EXTERNALSYM SSL_CTX_set_srp_verify_param_callback}
{$EXTERNALSYM SSL_CTX_set_srp_username_callback}
{$EXTERNALSYM SSL_CTX_set_srp_cb_arg}
{$EXTERNALSYM SSL_set_srp_server_param}
{$EXTERNALSYM SSL_set_srp_server_param_pw}
{$EXTERNALSYM SSL_CTX_set_client_hello_cb}
{$EXTERNALSYM SSL_client_hello_isv2}
{$EXTERNALSYM SSL_client_hello_get0_legacy_version}
{$EXTERNALSYM SSL_client_hello_get0_random}
{$EXTERNALSYM SSL_client_hello_get0_session_id}
{$EXTERNALSYM SSL_client_hello_get0_ciphers}
{$EXTERNALSYM SSL_client_hello_get0_compression_methods}
{$EXTERNALSYM SSL_client_hello_get1_extensions_present}
{$EXTERNALSYM SSL_client_hello_get0_ext}
{$EXTERNALSYM SSL_certs_clear}
{$EXTERNALSYM SSL_free}
{$EXTERNALSYM SSL_waiting_for_async}
{$EXTERNALSYM SSL_get_all_async_fds}
{$EXTERNALSYM SSL_get_changed_async_fds}
{$EXTERNALSYM SSL_accept}
{$EXTERNALSYM SSL_stateless}
{$EXTERNALSYM SSL_connect}
{$EXTERNALSYM SSL_read}
{$EXTERNALSYM SSL_read_ex}
{$EXTERNALSYM SSL_read_early_data}
{$EXTERNALSYM SSL_peek}
{$EXTERNALSYM SSL_peek_ex}
{$EXTERNALSYM SSL_write}
{$EXTERNALSYM SSL_write_ex}
{$EXTERNALSYM SSL_write_early_data}
{$EXTERNALSYM SSL_callback_ctrl}
{$EXTERNALSYM SSL_ctrl}
{$EXTERNALSYM SSL_CTX_ctrl}
{$EXTERNALSYM SSL_CTX_callback_ctrl}
{$EXTERNALSYM SSL_get_early_data_status}
{$EXTERNALSYM SSL_get_error}
{$EXTERNALSYM SSL_get_version}
{$EXTERNALSYM SSL_CTX_set_ssl_version}
{$EXTERNALSYM TLS_method}
{$EXTERNALSYM TLS_server_method}
{$EXTERNALSYM TLS_client_method}
{$EXTERNALSYM SSL_do_handshake}
{$EXTERNALSYM SSL_key_update}
{$EXTERNALSYM SSL_get_key_update_type}
{$EXTERNALSYM SSL_renegotiate}
{$EXTERNALSYM SSL_renegotiate_abbreviated}
{$EXTERNALSYM SSL_new_session_ticket}
{$EXTERNALSYM SSL_shutdown}
{$EXTERNALSYM SSL_CTX_set_post_handshake_auth}
{$EXTERNALSYM SSL_set_post_handshake_auth}
{$EXTERNALSYM SSL_renegotiate_pending}
{$EXTERNALSYM SSL_verify_client_post_handshake}
{$EXTERNALSYM SSL_CTX_get_ssl_method}
{$EXTERNALSYM SSL_get_ssl_method}
{$EXTERNALSYM SSL_set_ssl_method}
{$EXTERNALSYM SSL_alert_type_string_long}
{$EXTERNALSYM SSL_alert_type_string}
{$EXTERNALSYM SSL_alert_desc_string_long}
{$EXTERNALSYM SSL_alert_desc_string}
{$EXTERNALSYM SSL_CTX_set_client_CA_list}
{$EXTERNALSYM SSL_add_client_CA}
{$EXTERNALSYM SSL_CTX_add_client_CA}
{$EXTERNALSYM SSL_set_connect_state}
{$EXTERNALSYM SSL_set_accept_state}
{$EXTERNALSYM SSL_CIPHER_description}
{$EXTERNALSYM SSL_dup}
{$EXTERNALSYM SSL_get_certificate}
{$EXTERNALSYM SSL_get_privatekey}
{$EXTERNALSYM SSL_CTX_get0_certificate}
{$EXTERNALSYM SSL_CTX_get0_privatekey}
{$EXTERNALSYM SSL_CTX_set_quiet_shutdown}
{$EXTERNALSYM SSL_CTX_get_quiet_shutdown}
{$EXTERNALSYM SSL_set_quiet_shutdown}
{$EXTERNALSYM SSL_get_quiet_shutdown}
{$EXTERNALSYM SSL_set_shutdown}
{$EXTERNALSYM SSL_get_shutdown}
{$EXTERNALSYM SSL_version}
{$EXTERNALSYM SSL_client_version}
{$EXTERNALSYM SSL_CTX_set_default_verify_paths}
{$EXTERNALSYM SSL_CTX_set_default_verify_dir}
{$EXTERNALSYM SSL_CTX_set_default_verify_file}
{$EXTERNALSYM SSL_CTX_load_verify_locations}
{$EXTERNALSYM SSL_get_session}
{$EXTERNALSYM SSL_get1_session}
{$EXTERNALSYM SSL_get_SSL_CTX}
{$EXTERNALSYM SSL_set_SSL_CTX}
{$EXTERNALSYM SSL_set_info_callback}
{$EXTERNALSYM SSL_get_info_callback}
{$EXTERNALSYM SSL_get_state}
{$EXTERNALSYM SSL_set_verify_result}
{$EXTERNALSYM SSL_get_verify_result}
{$EXTERNALSYM SSL_get_client_random}
{$EXTERNALSYM SSL_get_server_random}
{$EXTERNALSYM SSL_SESSION_get_master_key}
{$EXTERNALSYM SSL_SESSION_set1_master_key}
{$EXTERNALSYM SSL_SESSION_get_max_fragment_length}
{$EXTERNALSYM SSL_set_ex_data}
{$EXTERNALSYM SSL_get_ex_data}
{$EXTERNALSYM SSL_SESSION_set_ex_data}
{$EXTERNALSYM SSL_SESSION_get_ex_data}
{$EXTERNALSYM SSL_CTX_set_ex_data}
{$EXTERNALSYM SSL_CTX_get_ex_data}
{$EXTERNALSYM SSL_get_ex_data_X509_STORE_CTX_idx}
{$EXTERNALSYM SSL_CTX_set_default_read_buffer_len}
{$EXTERNALSYM SSL_set_default_read_buffer_len}
{$EXTERNALSYM SSL_CTX_set_tmp_dh_callback}
{$EXTERNALSYM SSL_set_tmp_dh_callback}
{$EXTERNALSYM SSL_CIPHER_find}
{$EXTERNALSYM SSL_CIPHER_get_cipher_nid}
{$EXTERNALSYM SSL_CIPHER_get_digest_nid}
{$EXTERNALSYM SSL_set_session_ticket_ext}
{$EXTERNALSYM SSL_set_session_ticket_ext_cb}
{$EXTERNALSYM SSL_CTX_set_not_resumable_session_callback}
{$EXTERNALSYM SSL_set_not_resumable_session_callback}
{$EXTERNALSYM SSL_CTX_set_record_padding_callback}
{$EXTERNALSYM SSL_CTX_set_record_padding_callback_arg}
{$EXTERNALSYM SSL_CTX_get_record_padding_callback_arg}
{$EXTERNALSYM SSL_CTX_set_block_padding}
{$EXTERNALSYM SSL_set_record_padding_callback}
{$EXTERNALSYM SSL_set_record_padding_callback_arg}
{$EXTERNALSYM SSL_get_record_padding_callback_arg}
{$EXTERNALSYM SSL_set_block_padding}
{$EXTERNALSYM SSL_set_num_tickets}
{$EXTERNALSYM SSL_get_num_tickets}
{$EXTERNALSYM SSL_CTX_set_num_tickets}
{$EXTERNALSYM SSL_CTX_get_num_tickets}
{$EXTERNALSYM SSL_session_reused}
{$EXTERNALSYM SSL_is_server}
{$EXTERNALSYM SSL_CONF_CTX_new}
{$EXTERNALSYM SSL_CONF_CTX_finish}
{$EXTERNALSYM SSL_CONF_CTX_free}
{$EXTERNALSYM SSL_CONF_CTX_set_flags}
{$EXTERNALSYM SSL_CONF_CTX_clear_flags}
{$EXTERNALSYM SSL_CONF_CTX_set1_prefix}
{$EXTERNALSYM SSL_CONF_cmd}
{$EXTERNALSYM SSL_CONF_cmd_argv}
{$EXTERNALSYM SSL_CONF_cmd_value_type}
{$EXTERNALSYM SSL_CONF_CTX_set_ssl}
{$EXTERNALSYM SSL_CONF_CTX_set_ssl_ctx}
{$EXTERNALSYM SSL_add_ssl_module}
{$EXTERNALSYM SSL_config}
{$EXTERNALSYM SSL_CTX_config}
{$EXTERNALSYM DTLSv1_listen}
{$EXTERNALSYM SSL_enable_ct}
{$EXTERNALSYM SSL_CTX_enable_ct}
{$EXTERNALSYM SSL_ct_is_enabled}
{$EXTERNALSYM SSL_CTX_ct_is_enabled}
{$EXTERNALSYM SSL_CTX_set_default_ctlog_list_file}
{$EXTERNALSYM SSL_CTX_set_ctlog_list_file}
{$EXTERNALSYM SSL_CTX_set0_ctlog_store}
{$EXTERNALSYM SSL_set_security_level}
{$EXTERNALSYM SSL_set_security_callback}
{$EXTERNALSYM SSL_get_security_callback}
{$EXTERNALSYM SSL_set0_security_ex_data}
{$EXTERNALSYM SSL_get0_security_ex_data}
{$EXTERNALSYM SSL_CTX_set_security_level}
{$EXTERNALSYM SSL_CTX_get_security_level}
{$EXTERNALSYM SSL_CTX_get0_security_ex_data}
{$EXTERNALSYM SSL_CTX_set0_security_ex_data}
{$EXTERNALSYM OPENSSL_init_ssl}
{$EXTERNALSYM SSL_free_buffers}
{$EXTERNALSYM SSL_alloc_buffers}
{$EXTERNALSYM SSL_CTX_set_session_ticket_cb}
{$EXTERNALSYM SSL_SESSION_set1_ticket_appdata}
{$EXTERNALSYM SSL_SESSION_get0_ticket_appdata}
{$EXTERNALSYM DTLS_set_timer_cb}
{$EXTERNALSYM SSL_CTX_set_allow_early_data_cb}
{$EXTERNALSYM SSL_set_allow_early_data_cb}
{$EXTERNALSYM SSL_get0_peer_certificate}
{$EXTERNALSYM SSL_get1_peer_certificate}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function SSL_CTX_get_options(const ctx: PSSL_CTX): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_get_options(const s: PSSL): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_clear_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_clear_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_set_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
procedure SSL_CTX_sess_set_new_cb(ctx: PSSL_CTX; new_session_cb: SSL_CTX_sess_new_cb); cdecl; external CLibSSL;
function SSL_CTX_sess_get_new_cb(ctx: PSSL_CTX): SSL_CTX_sess_new_cb; cdecl; external CLibSSL;
procedure SSL_CTX_sess_set_remove_cb(ctx: PSSL_CTX; remove_session_cb: SSL_CTX_sess_remove_cb); cdecl; external CLibSSL;
function SSL_CTX_sess_get_remove_cb(ctx: PSSL_CTX): SSL_CTX_sess_remove_cb; cdecl; external CLibSSL;
procedure SSL_CTX_set_info_callback(ctx: PSSL_CTX; cb: SSL_CTX_info_callback); cdecl; external CLibSSL;
function SSL_CTX_get_info_callback(ctx: PSSL_CTX): SSL_CTX_info_callback; cdecl; external CLibSSL;
procedure SSL_CTX_set_client_cert_cb(ctx: PSSL_CTX; client_cert_cb: SSL_CTX_client_cert_cb); cdecl; external CLibSSL;
function SSL_CTX_get_client_cert_cb(ctx: PSSL_CTX): SSL_CTX_client_cert_cb; cdecl; external CLibSSL;
function SSL_CTX_set_client_cert_engine(ctx: PSSL_CTX; e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_cookie_generate_cb(ctx: PSSL_CTX; app_gen_cookie_cb: SSL_CTX_cookie_verify_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_cookie_verify_cb(ctx: PSSL_CTX; app_verify_cookie_cb: SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_stateless_cookie_generate_cb(ctx: PSSL_CTX; gen_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_stateless_cookie_verify_cb(ctx: PSSL_CTX; verify_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_alpn_select_cb(ctx: PSSL_CTX; cb: SSL_CTX_alpn_select_cb_func; arg: Pointer); cdecl; external CLibSSL;
procedure SSL_get0_alpn_selected(const ssl: PSSL; const data: PPByte; len: POpenSSL_C_UINT); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_client_callback(ctx: PSSL_CTX; cb: SSL_psk_client_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_client_callback(ssl: PSSL; cb: SSL_psk_client_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_server_callback(ctx: PSSL_CTX; cb: SSL_psk_server_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_server_callback(ssl: PSSL; cb: SSL_psk_server_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_find_session_callback(s: PSSL; cb: SSL_psk_find_session_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_find_session_callback(ctx: PSSL_CTX; cb: SSL_psk_find_session_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_use_session_callback(s: PSSL; cb: SSL_psk_use_session_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_use_session_callback(ctx: PSSL_CTX; cb: SSL_psk_use_session_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_keylog_callback(ctx: PSSL_CTX; cb: SSL_CTX_keylog_cb_func); cdecl; external CLibSSL;
function SSL_CTX_get_keylog_callback(const ctx: PSSL_CTX): SSL_CTX_keylog_cb_func; cdecl; external CLibSSL;
function SSL_CTX_set_max_early_data(ctx: PSSL_CTX; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_set_max_early_data(s: PSSL; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_CTX_set_recv_max_early_data(ctx: PSSL_CTX; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_recv_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_set_recv_max_early_data(s: PSSL; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_recv_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_in_init(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_in_before(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_is_init_finished(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_get_peer_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function BIO_f_ssl: PBIO_METHOD; cdecl; external CLibSSL;
function BIO_new_ssl(ctx: PSSL_CTX; client: TOpenSSL_C_INT): PBIO; cdecl; external CLibSSL;
function BIO_new_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl; external CLibSSL;
function BIO_new_buffer_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl; external CLibSSL;
function BIO_ssl_copy_session_id(to_: PBIO; from: PBIO): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_cipher_list(v1: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_new(const meth: PSSL_METHOD): PSSL_CTX; cdecl; external CLibSSL;
function SSL_CTX_set_timeout(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_get_timeout(const ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_get_cert_store(const v1: PSSL_CTX): PX509_STORE; cdecl; external CLibSSL;
function SSL_want(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_clear(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure BIO_ssl_shutdown(ssl_bio: PBIO); cdecl; external CLibSSL;
function SSL_CTX_up_ref(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_free(v1: PSSL_CTX); cdecl; external CLibSSL;
procedure SSL_CTX_set_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl; external CLibSSL;
procedure SSL_CTX_set1_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl; external CLibSSL;
procedure SSL_CTX_flush_sessions(ctx: PSSL_CTX; tm: TOpenSSL_C_LONG); cdecl; external CLibSSL;
function SSL_get_current_cipher(const s: PSSL): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_get_pending_cipher(const s: PSSL): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_CIPHER_get_bits(const c: PSSL_CIPHER; var alg_bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_version(const c: PSSL_CIPHER): PAnsiChar; cdecl; external CLibSSL;
function SSL_CIPHER_get_name(const c: PSSL_CIPHER): PAnsiChar; cdecl; external CLibSSL;
function SSL_CIPHER_standard_name(const c: PSSL_CIPHER): PAnsiChar; cdecl; external CLibSSL;
function OPENSSL_cipher_name(const rfc_name: PAnsiChar): PAnsiChar; cdecl; external CLibSSL;
function SSL_CIPHER_get_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_CIPHER_get_protocol_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT16; cdecl; external CLibSSL;
function SSL_CIPHER_get_kx_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_auth_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_handshake_digest(const c: PSSL_CIPHER): PEVP_MD; cdecl; external CLibSSL;
function SSL_CIPHER_is_aead(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_fd(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_rfd(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_wfd(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_cipher_list(const s: PSSL; n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_get_shared_ciphers(const s: PSSL; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_get_read_ahead(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_pending(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_has_pending(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_fd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_rfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_wfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set0_rbio(s: PSSL; rbio: PBIO); cdecl; external CLibSSL;
procedure SSL_set0_wbio(s: PSSL; wbio: PBIO); cdecl; external CLibSSL;
procedure SSL_set_bio(s: PSSL; rbio: PBIO; wbio: PBIO); cdecl; external CLibSSL;
function SSL_get_rbio(const s: PSSL): PBIO; cdecl; external CLibSSL;
function SSL_get_wbio(const s: PSSL): PBIO; cdecl; external CLibSSL;
function SSL_set_cipher_list(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_ciphersuites(ctx: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_ciphersuites(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_verify_mode(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_verify_depth(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_verify_callback(const s: PSSL): SSL_verify_cb; cdecl; external CLibSSL;
procedure SSL_set_read_ahead(s: PSSL; yes: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_set_verify(s: PSSL; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl; external CLibSSL;
procedure SSL_set_verify_depth(s: PSSL; depth: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_use_RSAPrivateKey(ssl: PSSL; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_RSAPrivateKey_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_PrivateKey(ssl: PSSL; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_serverinfo(ctx: PSSL_CTX; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_serverinfo_ex(ctx: PSSL_CTX; version: TOpenSSL_C_UINT; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_serverinfo_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_RSAPrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_PrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_RSAPrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate_chain_file(ssl: PSSL; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_load_client_CA_file(const file_: PAnsiChar): PSTACK_OF_X509_NAME; cdecl; external CLibSSL;
function SSL_add_file_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_add_dir_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const dir_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_state_string(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_rstate_string(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_state_string_long(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_rstate_string_long(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_SESSION_get_time(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_set_time(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_get_timeout(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_set_timeout(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_set_protocol_version(s: PSSL_SESSION; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_hostname(const s: PSSL_SESSION): PAnsiChar; cdecl; external CLibSSL;
function SSL_SESSION_set1_hostname(s: PSSL_SESSION; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_SESSION_get0_alpn_selected(const s: PSSL_SESSION; const alpn: PPByte; len: POpenSSL_C_SIZET); cdecl; external CLibSSL;
function SSL_SESSION_set1_alpn_selected(s: PSSL_SESSION; const alpn: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_cipher(const s: PSSL_SESSION): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_SESSION_set_cipher(s: PSSL_SESSION; const cipher: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_has_ticket(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get_ticket_lifetime_hint(const s: PSSL_SESSION): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
procedure SSL_SESSION_get0_ticket(const s: PSSL_SESSION; const tick: PPByte; len: POpenSSL_C_SIZET); cdecl; external CLibSSL;
function SSL_SESSION_get_max_early_data(const s: PSSL_SESSION): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_SESSION_set_max_early_data(s: PSSL_SESSION; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_copy_session_id(to_: PSSL; const from: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_peer(s: PSSL_SESSION): PX509; cdecl; external CLibSSL;
function SSL_SESSION_set1_id_context(s: PSSL_SESSION; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_set1_id(s: PSSL_SESSION; const sid: PByte; sid_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_is_resumable(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_new: PSSL_SESSION; cdecl; external CLibSSL;
function SSL_SESSION_dup(src: PSSL_SESSION): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_SESSION_get_id(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl; external CLibSSL;
function SSL_SESSION_get0_id_context(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl; external CLibSSL;
function SSL_SESSION_get_compress_id(const s: PSSL_SESSION): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_SESSION_print(fp: PBIO; const ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_print_keylog(bp: PBIO; const x: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_up_ref(ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_SESSION_free(ses: PSSL_SESSION); cdecl; external CLibSSL;
function SSL_set_session(to_: PSSL; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_add_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_remove_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_generate_session_id(ctx: PSSL_CTX; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_generate_session_id(s: PSSL; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_has_matching_session_id(const s: PSSL; const id: PByte; id_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function d2i_SSL_SESSION(a: PPSSL_SESSION; const pp: PPByte; length: TOpenSSL_C_LONG): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_CTX_get_verify_mode(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_verify_depth(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_verify_callback(const ctx: PSSL_CTX): SSL_verify_cb; cdecl; external CLibSSL;
procedure SSL_CTX_set_verify(ctx: PSSL_CTX; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_verify_depth(ctx: PSSL_CTX; depth: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_CTX_set_cert_verify_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_cert_verify_callback_cb; arg: Pointer); cdecl; external CLibSSL;
procedure SSL_CTX_set_cert_cb(c: PSSL_CTX; cb: SSL_CTX_set_cert_cb_cb; arg: Pointer); cdecl; external CLibSSL;
function SSL_CTX_use_RSAPrivateKey(ctx: PSSL_CTX; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_RSAPrivateKey_ASN1(ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_PrivateKey(ctx: PSSL_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate(ctx: PSSL_CTX; x: X509): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate_ASN1(ctx: PSSL_CTX; len: TOpenSSL_C_INT; const d: PByte): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: pem_password_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer); cdecl; external CLibSSL;
function SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): pem_password_cb; cdecl; external CLibSSL;
function SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer; cdecl; external CLibSSL;
procedure SSL_set_default_passwd_cb(s: PSSL; cb: pem_password_cb); cdecl; external CLibSSL;
procedure SSL_set_default_passwd_cb_userdata(s: PSSL; u: Pointer); cdecl; external CLibSSL;
function SSL_get_default_passwd_cb(s: PSSL): pem_password_cb; cdecl; external CLibSSL;
function SSL_get_default_passwd_cb_userdata(s: PSSL): Pointer; cdecl; external CLibSSL;
function SSL_CTX_check_private_key(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_check_private_key(const ctx: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_session_id_context(ctx: PSSL_CTX; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_new(ctx: PSSL_CTX): PSSL; cdecl; external CLibSSL;
function SSL_up_ref(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_is_dtls(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_session_id_context(ssl: PSSL; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_purpose(ctx: PSSL_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_purpose(ssl: PSSL; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_trust(ctx: PSSL_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_trust(ssl: PSSL; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_add1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_peername(s: PSSL): PAnsiChar; cdecl; external CLibSSL;
procedure SSL_set_hostflags(s: PSSL; flags: TOpenSSL_C_UINT); cdecl; external CLibSSL;
function SSL_CTX_dane_enable(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_dane_mtype_set(ctx: PSSL_CTX; const md: PEVP_MD; mtype: TOpenSSL_C_UINT8; ord: TOpenSSL_C_UINT8): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_dane_enable(s: PSSL; const basedomain: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_dane_tlsa_add(s: PSSL; usage: TOpenSSL_C_UINT8; selector: TOpenSSL_C_UINT8; mtype: TOpenSSL_C_UINT8; const data: PByte; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_dane_authority(s: PSSL; mcert: PPX509; mspki: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_dane_tlsa(s: PSSL; usage: POpenSSL_C_UINT8; selector: POpenSSL_C_UINT8; mtype: POpenSSL_C_UINT8; const data: PPByte; dlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_dane(ssl: PSSL): PSSL_DANE; cdecl; external CLibSSL;
function SSL_CTX_dane_set_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_dane_clear_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_dane_set_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_dane_clear_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_set1_param(ctx: PSSL_CTX; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set1_param(ssl: PSSL; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get0_param(ctx: PSSL_CTX): PX509_VERIFY_PARAM; cdecl; external CLibSSL;
function SSL_get0_param(ssl: PSSL): PX509_VERIFY_PARAM; cdecl; external CLibSSL;
function SSL_CTX_set_srp_username(ctx: PSSL_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_password(ctx: PSSL_CTX; password: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_strength(ctx: PSSL_CTX; strength: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_client_pwd_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_client_pwd_callback_cb): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_verify_param_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_verify_param_callback_cb): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_username_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_username_callback_cb): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_cb_arg(ctx: PSSL_CTX; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_srp_server_param(s: PSSL; const N: PBIGNUm; const g: PBIGNUm; sa: PBIGNUm; v: PBIGNUm; info: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_srp_server_param_pw(s: PSSL; const user: PAnsiChar; const pass: PAnsiChar; const grp: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_client_hello_cb(c: PSSL_CTX; cb: SSL_client_hello_cb_fn; arg: Pointer); cdecl; external CLibSSL;
function SSL_client_hello_isv2(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_client_hello_get0_legacy_version(s: PSSL): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_client_hello_get0_random(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get0_session_id(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get0_ciphers(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get0_compression_methods(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get1_extensions_present(s: PSSL; out_: PPOpenSSL_C_INT; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_client_hello_get0_ext(s: PSSL; type_: TOpenSSL_C_UINT; const out_: PPByte; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_certs_clear(s: PSSL); cdecl; external CLibSSL;
procedure SSL_free(ssl: PSSL); cdecl; external CLibSSL;
function SSL_waiting_for_async(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_all_async_fds(s: PSSL; fds: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_changed_async_fds(s: PSSL; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_accept(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_stateless(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_connect(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_read(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_read_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_read_early_data(s: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_peek(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_peek_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_write(ssl: PSSL; const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_write_ex(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_write_early_data(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_callback_ctrl(v1: PSSL; v2: TOpenSSL_C_INT; v3: SSL_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_ctrl(ssl: PSSL; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_ctrl(ctx: PSSL_CTX; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_callback_ctrl(v1: PSSL_CTX; v2: TOpenSSL_C_INT; v3: SSL_CTX_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_get_early_data_status(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_error(const s: PSSL; ret_code: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_version(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_CTX_set_ssl_version(ctx: PSSL_CTX; const meth: PSSL_METHOD): TOpenSSL_C_INT; cdecl; external CLibSSL;
function TLS_method: PSSL_METHOD; cdecl; external CLibSSL;
function TLS_server_method: PSSL_METHOD; cdecl; external CLibSSL;
function TLS_client_method: PSSL_METHOD; cdecl; external CLibSSL;
function SSL_do_handshake(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_key_update(s: PSSL; updatetype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_key_update_type(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_renegotiate(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_renegotiate_abbreviated(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_new_session_ticket(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_shutdown(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_post_handshake_auth(ctx: PSSL_CTX; val: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_set_post_handshake_auth(s: PSSL; val: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_renegotiate_pending(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_verify_client_post_handshake(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_ssl_method(const ctx: PSSL_CTX): PSSL_METHOD; cdecl; external CLibSSL;
function SSL_get_ssl_method(const s: PSSL): PSSL_METHOD; cdecl; external CLibSSL;
function SSL_set_ssl_method(s: PSSL; const method: PSSL_METHOD): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_alert_type_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_alert_type_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_alert_desc_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_alert_desc_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
procedure SSL_CTX_set_client_CA_list(ctx: PSSL_CTX; name_list: PSTACK_OF_X509_NAME); cdecl; external CLibSSL;
function SSL_add_client_CA(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_add_client_CA(ctx: PSSL_CTX; x: PX509): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_connect_state(s: PSSL); cdecl; external CLibSSL;
procedure SSL_set_accept_state(s: PSSL); cdecl; external CLibSSL;
function SSL_CIPHER_description(cipher: PSSL_CIPHER; buf: PAnsiChar; size_ :TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_dup(ssl: PSSL): PSSL; cdecl; external CLibSSL;
function SSL_get_certificate(const ssl: PSSL): PX509; cdecl; external CLibSSL;
function SSL_get_privatekey(const ssl: PSSL): PEVP_PKEY; cdecl; external CLibSSL;
function SSL_CTX_get0_certificate(const ctx: PSSL_CTX): PX509; cdecl; external CLibSSL;
function SSL_CTX_get0_privatekey(const ctx: PSSL_CTX): PEVP_PKEY; cdecl; external CLibSSL;
procedure SSL_CTX_set_quiet_shutdown(ctx: PSSL_CTX; mode: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_CTX_get_quiet_shutdown(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_quiet_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_get_quiet_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_get_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_version(const ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_client_version(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_verify_paths(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_verify_dir(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_verify_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_load_verify_locations(ctx: PSSL_CTX; const CAfile: PAnsiChar; const CApath: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_session(const ssl: PSSL): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_get1_session(ssl: PSSL): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_get_SSL_CTX(const ssl: PSSL): PSSL_CTX; cdecl; external CLibSSL;
function SSL_set_SSL_CTX(ssl: PSSL; ctx: PSSL_CTX): PSSL_CTX; cdecl; external CLibSSL;
procedure SSL_set_info_callback(ssl: PSSL; cb: SSL_info_callback); cdecl; external CLibSSL;
function SSL_get_info_callback(const ssl: PSSL): SSL_info_callback; cdecl; external CLibSSL;
function SSL_get_state(const ssl: PSSL): OSSL_HANDSHAKE_STATE; cdecl; external CLibSSL;
procedure SSL_set_verify_result(ssl: PSSL; v: TOpenSSL_C_LONG); cdecl; external CLibSSL;
function SSL_get_verify_result(const ssl: PSSL): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_get_client_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_get_server_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_SESSION_get_master_key(const sess: PSSL_SESSION; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_SESSION_set1_master_key(sess: PSSL_SESSION; const in_: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get_max_fragment_length(const sess: PSSL_SESSION): TOpenSSL_C_UINT8; cdecl; external CLibSSL;
function SSL_set_ex_data(ssl: PSSL; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_ex_data(const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibSSL;
function SSL_SESSION_set_ex_data(ss: PSSL_SESSION; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get_ex_data(const ss: PSSL_SESSION; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibSSL;
function SSL_CTX_set_ex_data(ssl: PSSL_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_ex_data(const ssl: PSSL_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibSSL;
function SSL_get_ex_data_X509_STORE_CTX_idx: TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_default_read_buffer_len(ctx: PSSL_CTX; len: TOpenSSL_C_SIZET); cdecl; external CLibSSL;
procedure SSL_set_default_read_buffer_len(s: PSSL; len: TOpenSSL_C_SIZET); cdecl; external CLibSSL;
procedure SSL_CTX_set_tmp_dh_callback(ctx: PSSL_CTX; dh: SSL_CTX_set_tmp_dh_callback_dh); cdecl; external CLibSSL;
procedure SSL_set_tmp_dh_callback(ssl: PSSL; dh: SSL_set_tmp_dh_callback_dh); cdecl; external CLibSSL;
function SSL_CIPHER_find(ssl: PSSL; const ptr: PByte): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_CIPHER_get_cipher_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_digest_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_session_ticket_ext(s: PSSL; ext_data: Pointer; ext_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_session_ticket_ext_cb(s: PSSL; cb: tls_session_ticket_ext_cb_fn; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_not_resumable_session_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_not_resumable_session_callback_cb); cdecl; external CLibSSL;
procedure SSL_set_not_resumable_session_callback(ssl: PSSL; cb: SSL_set_not_resumable_session_callback_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_record_padding_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_record_padding_callback_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_record_padding_callback_arg(ctx: PSSL_CTX; arg: Pointer); cdecl; external CLibSSL;
function SSL_CTX_get_record_padding_callback_arg(const ctx: PSSL_CTX): Pointer; cdecl; external CLibSSL;
function SSL_CTX_set_block_padding(ctx: PSSL_CTX; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_record_padding_callback(ssl: PSSL; cb: SSL_set_record_padding_callback_cb); cdecl; external CLibSSL;
procedure SSL_set_record_padding_callback_arg(ssl: PSSL; arg: Pointer); cdecl; external CLibSSL;
function SSL_get_record_padding_callback_arg(const ssl: PSSL): Pointer; cdecl; external CLibSSL;
function SSL_set_block_padding(ssl: PSSL; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_num_tickets(s: PSSL; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_num_tickets(const s: PSSL): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_CTX_set_num_tickets(ctx: PSSL_CTX; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_num_tickets(const ctx: PSSL_CTX): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_session_reused(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_is_server(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_CTX_new: PSSL_CONF_CTX; cdecl; external CLibSSL;
function SSL_CONF_CTX_finish(cctx: PSSL_CONF_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CONF_CTX_free(cctx: PSSL_CONF_CTX); cdecl; external CLibSSL;
function SSL_CONF_CTX_set_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_CONF_CTX_clear_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_CONF_CTX_set1_prefix(cctx: PSSL_CONF_CTX; const pre: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_cmd(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_cmd_argv(cctx: PSSL_CONF_CTX; pargc: POpenSSL_C_INT; pargv: PPPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_cmd_value_type(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CONF_CTX_set_ssl(cctx: PSSL_CONF_CTX; ssl: PSSL); cdecl; external CLibSSL;
procedure SSL_CONF_CTX_set_ssl_ctx(cctx: PSSL_CONF_CTX; ctx: PSSL_CTX); cdecl; external CLibSSL;
procedure SSL_add_ssl_module; cdecl; external CLibSSL;
function SSL_config(s: PSSL; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_config(ctx: PSSL_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function DTLSv1_listen(s: PSSL; client: PBIO_ADDr): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_enable_ct(s: PSSL; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_enable_ct(ctx: PSSL_CTX; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_ct_is_enabled(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_ct_is_enabled(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_ctlog_list_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_ctlog_list_file(ctx: PSSL_CTX; const path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set0_ctlog_store(ctx: PSSL_CTX; logs: PCTLOG_STORE); cdecl; external CLibSSL;
procedure SSL_set_security_level(s: PSSL; level: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_set_security_callback(s: PSSL; cb: SSL_security_callback); cdecl; external CLibSSL;
function SSL_get_security_callback(const s: PSSL): SSL_security_callback; cdecl; external CLibSSL;
procedure SSL_set0_security_ex_data(s: PSSL; ex: Pointer); cdecl; external CLibSSL;
function SSL_get0_security_ex_data(const s: PSSL): Pointer; cdecl; external CLibSSL;
procedure SSL_CTX_set_security_level(ctx: PSSL_CTX; level: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_CTX_get_security_level(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get0_security_ex_data(const ctx: PSSL_CTX): Pointer; cdecl; external CLibSSL;
procedure SSL_CTX_set0_security_ex_data(ctx: PSSL_CTX; ex: Pointer); cdecl; external CLibSSL;
function OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_free_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_alloc_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_session_ticket_cb(ctx: PSSL_CTX; gen_cb: SSL_CTX_generate_session_ticket_fn; dec_cb: SSL_CTX_decrypt_session_ticket_fn; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_set1_ticket_appdata(ss: PSSL_SESSION; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_ticket_appdata(ss: PSSL_SESSION; data: PPointer; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure DTLS_set_timer_cb(s: PSSL; cb: DTLS_timer_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_allow_early_data_cb(ctx: PSSL_CTX; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl; external CLibSSL;
procedure SSL_set_allow_early_data_cb(s: PSSL; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl; external CLibSSL;
function SSL_get0_peer_certificate(const s: PSSL): PX509; cdecl; {introduced 3.3.0 } external CLibSSL;
function SSL_get1_peer_certificate(const s: PSSL): PX509; cdecl; {introduced 3.3.0 } external CLibSSL;





{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_app_data(const ssl: PSSL): Pointer; {removed 1.0.0}
function SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function SSLeay_add_ssl_algorithms: TOpenSSL_C_INT; {removed 1.0.0}
procedure SSL_load_error_strings; {removed 1.1.0}
function SSL_get_peer_certificate(const s: PSSL): PX509; {removed 3.0.0}
function SSL_library_init: TOpenSSL_C_INT; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  SSL_CTX_get_options: function (const ctx: PSSL_CTX): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_get_options: function (const s: PSSL): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_CTX_clear_options: function (ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_clear_options: function (s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_CTX_set_options: function (ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_set_options: function (s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_CTX_sess_set_new_cb: procedure (ctx: PSSL_CTX; new_session_cb: SSL_CTX_sess_new_cb); cdecl = nil;
  SSL_CTX_sess_get_new_cb: function (ctx: PSSL_CTX): SSL_CTX_sess_new_cb; cdecl = nil;
  SSL_CTX_sess_set_remove_cb: procedure (ctx: PSSL_CTX; remove_session_cb: SSL_CTX_sess_remove_cb); cdecl = nil;
  SSL_CTX_sess_get_remove_cb: function (ctx: PSSL_CTX): SSL_CTX_sess_remove_cb; cdecl = nil;
  SSL_CTX_set_info_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_info_callback); cdecl = nil;
  SSL_CTX_get_info_callback: function (ctx: PSSL_CTX): SSL_CTX_info_callback; cdecl = nil;
  SSL_CTX_set_client_cert_cb: procedure (ctx: PSSL_CTX; client_cert_cb: SSL_CTX_client_cert_cb); cdecl = nil;
  SSL_CTX_get_client_cert_cb: function (ctx: PSSL_CTX): SSL_CTX_client_cert_cb; cdecl = nil;
  SSL_CTX_set_client_cert_engine: function (ctx: PSSL_CTX; e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_cookie_generate_cb: procedure (ctx: PSSL_CTX; app_gen_cookie_cb: SSL_CTX_cookie_verify_cb); cdecl = nil;
  SSL_CTX_set_cookie_verify_cb: procedure (ctx: PSSL_CTX; app_verify_cookie_cb: SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb); cdecl = nil;
  SSL_CTX_set_stateless_cookie_generate_cb: procedure (ctx: PSSL_CTX; gen_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb); cdecl = nil;
  SSL_CTX_set_stateless_cookie_verify_cb: procedure (ctx: PSSL_CTX; verify_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb); cdecl = nil;
  SSL_CTX_set_alpn_select_cb: procedure (ctx: PSSL_CTX; cb: SSL_CTX_alpn_select_cb_func; arg: Pointer); cdecl = nil;
  SSL_get0_alpn_selected: procedure (const ssl: PSSL; const data: PPByte; len: POpenSSL_C_UINT); cdecl = nil;
  SSL_CTX_set_psk_client_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_client_cb_func); cdecl = nil;
  SSL_set_psk_client_callback: procedure (ssl: PSSL; cb: SSL_psk_client_cb_func); cdecl = nil;
  SSL_CTX_set_psk_server_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_server_cb_func); cdecl = nil;
  SSL_set_psk_server_callback: procedure (ssl: PSSL; cb: SSL_psk_server_cb_func); cdecl = nil;
  SSL_set_psk_find_session_callback: procedure (s: PSSL; cb: SSL_psk_find_session_cb_func); cdecl = nil;
  SSL_CTX_set_psk_find_session_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_find_session_cb_func); cdecl = nil;
  SSL_set_psk_use_session_callback: procedure (s: PSSL; cb: SSL_psk_use_session_cb_func); cdecl = nil;
  SSL_CTX_set_psk_use_session_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_use_session_cb_func); cdecl = nil;
  SSL_CTX_set_keylog_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_keylog_cb_func); cdecl = nil;
  SSL_CTX_get_keylog_callback: function (const ctx: PSSL_CTX): SSL_CTX_keylog_cb_func; cdecl = nil;
  SSL_CTX_set_max_early_data: function (ctx: PSSL_CTX; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get_max_early_data: function (const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl = nil;
  SSL_set_max_early_data: function (s: PSSL; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_max_early_data: function (const s: PSSL): TOpenSSL_C_UINT32; cdecl = nil;
  SSL_CTX_set_recv_max_early_data: function (ctx: PSSL_CTX; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get_recv_max_early_data: function (const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl = nil;
  SSL_set_recv_max_early_data: function (s: PSSL; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_recv_max_early_data: function (const s: PSSL): TOpenSSL_C_UINT32; cdecl = nil;
  SSL_in_init: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_in_before: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_is_init_finished: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_finished: function (const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_get_peer_finished: function (const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  BIO_f_ssl: function : PBIO_METHOD; cdecl = nil;
  BIO_new_ssl: function (ctx: PSSL_CTX; client: TOpenSSL_C_INT): PBIO; cdecl = nil;
  BIO_new_ssl_connect: function (ctx: PSSL_CTX): PBIO; cdecl = nil;
  BIO_new_buffer_ssl_connect: function (ctx: PSSL_CTX): PBIO; cdecl = nil;
  BIO_ssl_copy_session_id: function (to_: PBIO; from: PBIO): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_cipher_list: function (v1: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_new: function (const meth: PSSL_METHOD): PSSL_CTX; cdecl = nil;
  SSL_CTX_set_timeout: function (ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil;
  SSL_CTX_get_timeout: function (const ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = nil;
  SSL_CTX_get_cert_store: function (const v1: PSSL_CTX): PX509_STORE; cdecl = nil;
  SSL_want: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_clear: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  BIO_ssl_shutdown: procedure (ssl_bio: PBIO); cdecl = nil;
  SSL_CTX_up_ref: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_free: procedure (v1: PSSL_CTX); cdecl = nil;
  SSL_CTX_set_cert_store: procedure (v1: PSSL_CTX; v2: PX509_STORE); cdecl = nil;
  SSL_CTX_set1_cert_store: procedure (v1: PSSL_CTX; v2: PX509_STORE); cdecl = nil;
  SSL_CTX_flush_sessions: procedure (ctx: PSSL_CTX; tm: TOpenSSL_C_LONG); cdecl = nil;
  SSL_get_current_cipher: function (const s: PSSL): PSSL_CIPHER; cdecl = nil;
  SSL_get_pending_cipher: function (const s: PSSL): PSSL_CIPHER; cdecl = nil;
  SSL_CIPHER_get_bits: function (const c: PSSL_CIPHER; var alg_bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CIPHER_get_version: function (const c: PSSL_CIPHER): PAnsiChar; cdecl = nil;
  SSL_CIPHER_get_name: function (const c: PSSL_CIPHER): PAnsiChar; cdecl = nil;
  SSL_CIPHER_standard_name: function (const c: PSSL_CIPHER): PAnsiChar; cdecl = nil;
  OPENSSL_cipher_name: function (const rfc_name: PAnsiChar): PAnsiChar; cdecl = nil;
  SSL_CIPHER_get_id: function (const c: PSSL_CIPHER): TOpenSSL_C_UINT32; cdecl = nil;
  SSL_CIPHER_get_protocol_id: function (const c: PSSL_CIPHER): TOpenSSL_C_UINT16; cdecl = nil;
  SSL_CIPHER_get_kx_nid: function (const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = nil;
  SSL_CIPHER_get_auth_nid: function (const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = nil;
  SSL_CIPHER_get_handshake_digest: function (const c: PSSL_CIPHER): PEVP_MD; cdecl = nil;
  SSL_CIPHER_is_aead: function (const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_fd: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_rfd: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_wfd: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_cipher_list: function (const s: PSSL; n: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  SSL_get_shared_ciphers: function (const s: PSSL; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  SSL_get_read_ahead: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_pending: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_has_pending: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_fd: function (s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_rfd: function (s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_wfd: function (s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_set0_rbio: procedure (s: PSSL; rbio: PBIO); cdecl = nil;
  SSL_set0_wbio: procedure (s: PSSL; wbio: PBIO); cdecl = nil;
  SSL_set_bio: procedure (s: PSSL; rbio: PBIO; wbio: PBIO); cdecl = nil;
  SSL_get_rbio: function (const s: PSSL): PBIO; cdecl = nil;
  SSL_get_wbio: function (const s: PSSL): PBIO; cdecl = nil;
  SSL_set_cipher_list: function (s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_ciphersuites: function (ctx: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_ciphersuites: function (s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_verify_mode: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_verify_depth: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_verify_callback: function (const s: PSSL): SSL_verify_cb; cdecl = nil;
  SSL_set_read_ahead: procedure (s: PSSL; yes: TOpenSSL_C_INT); cdecl = nil;
  SSL_set_verify: procedure (s: PSSL; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl = nil;
  SSL_set_verify_depth: procedure (s: PSSL; depth: TOpenSSL_C_INT); cdecl = nil;
  SSL_use_RSAPrivateKey: function (ssl: PSSL; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_RSAPrivateKey_ASN1: function (ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_PrivateKey: function (ssl: PSSL; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_PrivateKey_ASN1: function (pk: TOpenSSL_C_INT; ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_certificate: function (ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_certificate_ASN1: function (ssl: PSSL; const d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_serverinfo: function (ctx: PSSL_CTX; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_serverinfo_ex: function (ctx: PSSL_CTX; version: TOpenSSL_C_UINT; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_serverinfo_file: function (ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_RSAPrivateKey_file: function (ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_PrivateKey_file: function (ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_certificate_file: function (ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_RSAPrivateKey_file: function (ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_PrivateKey_file: function (ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_certificate_file: function (ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_certificate_chain_file: function (ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_use_certificate_chain_file: function (ssl: PSSL; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_load_client_CA_file: function (const file_: PAnsiChar): PSTACK_OF_X509_NAME; cdecl = nil;
  SSL_add_file_cert_subjects_to_stack: function (stackCAs: PSTACK_OF_X509_NAME; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_add_dir_cert_subjects_to_stack: function (stackCAs: PSTACK_OF_X509_NAME; const dir_: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_state_string: function (const s: PSSL): PAnsiChar; cdecl = nil;
  SSL_rstate_string: function (const s: PSSL): PAnsiChar; cdecl = nil;
  SSL_state_string_long: function (const s: PSSL): PAnsiChar; cdecl = nil;
  SSL_rstate_string_long: function (const s: PSSL): PAnsiChar; cdecl = nil;
  SSL_SESSION_get_time: function (const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl = nil;
  SSL_SESSION_set_time: function (s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil;
  SSL_SESSION_get_timeout: function (const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl = nil;
  SSL_SESSION_set_timeout: function (s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil;
  SSL_SESSION_get_protocol_version: function (const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_set_protocol_version: function (s: PSSL_SESSION; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get0_hostname: function (const s: PSSL_SESSION): PAnsiChar; cdecl = nil;
  SSL_SESSION_set1_hostname: function (s: PSSL_SESSION; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get0_alpn_selected: procedure (const s: PSSL_SESSION; const alpn: PPByte; len: POpenSSL_C_SIZET); cdecl = nil;
  SSL_SESSION_set1_alpn_selected: function (s: PSSL_SESSION; const alpn: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get0_cipher: function (const s: PSSL_SESSION): PSSL_CIPHER; cdecl = nil;
  SSL_SESSION_set_cipher: function (s: PSSL_SESSION; const cipher: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_has_ticket: function (const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get_ticket_lifetime_hint: function (const s: PSSL_SESSION): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_SESSION_get0_ticket: procedure (const s: PSSL_SESSION; const tick: PPByte; len: POpenSSL_C_SIZET); cdecl = nil;
  SSL_SESSION_get_max_early_data: function (const s: PSSL_SESSION): TOpenSSL_C_UINT32; cdecl = nil;
  SSL_SESSION_set_max_early_data: function (s: PSSL_SESSION; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = nil;
  SSL_copy_session_id: function (to_: PSSL; const from: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get0_peer: function (s: PSSL_SESSION): PX509; cdecl = nil;
  SSL_SESSION_set1_id_context: function (s: PSSL_SESSION; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_set1_id: function (s: PSSL_SESSION; const sid: PByte; sid_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_is_resumable: function (const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_new: function : PSSL_SESSION; cdecl = nil;
  SSL_SESSION_dup: function (src: PSSL_SESSION): PSSL_SESSION; cdecl = nil;
  SSL_SESSION_get_id: function (const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl = nil;
  SSL_SESSION_get0_id_context: function (const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl = nil;
  SSL_SESSION_get_compress_id: function (const s: PSSL_SESSION): TOpenSSL_C_UINT; cdecl = nil;
  SSL_SESSION_print: function (fp: PBIO; const ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_print_keylog: function (bp: PBIO; const x: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_up_ref: function (ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_free: procedure (ses: PSSL_SESSION); cdecl = nil;
  SSL_set_session: function (to_: PSSL; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_add_session: function (ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_remove_session: function (ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_generate_session_id: function (ctx: PSSL_CTX; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_generate_session_id: function (s: PSSL; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl = nil;
  SSL_has_matching_session_id: function (const s: PSSL; const id: PByte; id_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  d2i_SSL_SESSION: function (a: PPSSL_SESSION; const pp: PPByte; length: TOpenSSL_C_LONG): PSSL_SESSION; cdecl = nil;
  SSL_CTX_get_verify_mode: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get_verify_depth: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get_verify_callback: function (const ctx: PSSL_CTX): SSL_verify_cb; cdecl = nil;
  SSL_CTX_set_verify: procedure (ctx: PSSL_CTX; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl = nil;
  SSL_CTX_set_verify_depth: procedure (ctx: PSSL_CTX; depth: TOpenSSL_C_INT); cdecl = nil;
  SSL_CTX_set_cert_verify_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_set_cert_verify_callback_cb; arg: Pointer); cdecl = nil;
  SSL_CTX_set_cert_cb: procedure (c: PSSL_CTX; cb: SSL_CTX_set_cert_cb_cb; arg: Pointer); cdecl = nil;
  SSL_CTX_use_RSAPrivateKey: function (ctx: PSSL_CTX; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_RSAPrivateKey_ASN1: function (ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_PrivateKey: function (ctx: PSSL_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_PrivateKey_ASN1: function (pk: TOpenSSL_C_INT; ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_certificate: function (ctx: PSSL_CTX; x: X509): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_use_certificate_ASN1: function (ctx: PSSL_CTX; len: TOpenSSL_C_INT; const d: PByte): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_default_passwd_cb: procedure (ctx: PSSL_CTX; cb: pem_password_cb); cdecl = nil;
  SSL_CTX_set_default_passwd_cb_userdata: procedure (ctx: PSSL_CTX; u: Pointer); cdecl = nil;
  SSL_CTX_get_default_passwd_cb: function (ctx: PSSL_CTX): pem_password_cb; cdecl = nil;
  SSL_CTX_get_default_passwd_cb_userdata: function (ctx: PSSL_CTX): Pointer; cdecl = nil;
  SSL_set_default_passwd_cb: procedure (s: PSSL; cb: pem_password_cb); cdecl = nil;
  SSL_set_default_passwd_cb_userdata: procedure (s: PSSL; u: Pointer); cdecl = nil;
  SSL_get_default_passwd_cb: function (s: PSSL): pem_password_cb; cdecl = nil;
  SSL_get_default_passwd_cb_userdata: function (s: PSSL): Pointer; cdecl = nil;
  SSL_CTX_check_private_key: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_check_private_key: function (const ctx: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_session_id_context: function (ctx: PSSL_CTX; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  SSL_new: function (ctx: PSSL_CTX): PSSL; cdecl = nil;
  SSL_up_ref: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_is_dtls: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_session_id_context: function (ssl: PSSL; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_purpose: function (ctx: PSSL_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_purpose: function (ssl: PSSL; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_trust: function (ctx: PSSL_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_trust: function (ssl: PSSL; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_set1_host: function (s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_add1_host: function (s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_get0_peername: function (s: PSSL): PAnsiChar; cdecl = nil;
  SSL_set_hostflags: procedure (s: PSSL; flags: TOpenSSL_C_UINT); cdecl = nil;
  SSL_CTX_dane_enable: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_dane_mtype_set: function (ctx: PSSL_CTX; const md: PEVP_MD; mtype: TOpenSSL_C_UINT8; ord: TOpenSSL_C_UINT8): TOpenSSL_C_INT; cdecl = nil;
  SSL_dane_enable: function (s: PSSL; const basedomain: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_dane_tlsa_add: function (s: PSSL; usage: TOpenSSL_C_UINT8; selector: TOpenSSL_C_UINT8; mtype: TOpenSSL_C_UINT8; const data: PByte; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_get0_dane_authority: function (s: PSSL; mcert: PPX509; mspki: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  SSL_get0_dane_tlsa: function (s: PSSL; usage: POpenSSL_C_UINT8; selector: POpenSSL_C_UINT8; mtype: POpenSSL_C_UINT8; const data: PPByte; dlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_get0_dane: function (ssl: PSSL): PSSL_DANE; cdecl = nil;
  SSL_CTX_dane_set_flags: function (ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_CTX_dane_clear_flags: function (ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_dane_set_flags: function (ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_dane_clear_flags: function (ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = nil;
  SSL_CTX_set1_param: function (ctx: PSSL_CTX; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  SSL_set1_param: function (ssl: PSSL; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get0_param: function (ctx: PSSL_CTX): PX509_VERIFY_PARAM; cdecl = nil;
  SSL_get0_param: function (ssl: PSSL): PX509_VERIFY_PARAM; cdecl = nil;
  SSL_CTX_set_srp_username: function (ctx: PSSL_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_srp_password: function (ctx: PSSL_CTX; password: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_srp_strength: function (ctx: PSSL_CTX; strength: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_srp_client_pwd_callback: function (ctx: PSSL_CTX; cb: SSL_CTX_set_srp_client_pwd_callback_cb): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_srp_verify_param_callback: function (ctx: PSSL_CTX; cb: SSL_CTX_set_srp_verify_param_callback_cb): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_srp_username_callback: function (ctx: PSSL_CTX; cb: SSL_CTX_set_srp_username_callback_cb): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_srp_cb_arg: function (ctx: PSSL_CTX; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_srp_server_param: function (s: PSSL; const N: PBIGNUm; const g: PBIGNUm; sa: PBIGNUm; v: PBIGNUm; info: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_srp_server_param_pw: function (s: PSSL; const user: PAnsiChar; const pass: PAnsiChar; const grp: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_client_hello_cb: procedure (c: PSSL_CTX; cb: SSL_client_hello_cb_fn; arg: Pointer); cdecl = nil;
  SSL_client_hello_isv2: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_client_hello_get0_legacy_version: function (s: PSSL): TOpenSSL_C_UINT; cdecl = nil;
  SSL_client_hello_get0_random: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_client_hello_get0_session_id: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_client_hello_get0_ciphers: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_client_hello_get0_compression_methods: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_client_hello_get1_extensions_present: function (s: PSSL; out_: PPOpenSSL_C_INT; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_client_hello_get0_ext: function (s: PSSL; type_: TOpenSSL_C_UINT; const out_: PPByte; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_certs_clear: procedure (s: PSSL); cdecl = nil;
  SSL_free: procedure (ssl: PSSL); cdecl = nil;
  SSL_waiting_for_async: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_all_async_fds: function (s: PSSL; fds: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_changed_async_fds: function (s: PSSL; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_accept: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_stateless: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_connect: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_read: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_read_ex: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_read_early_data: function (s: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_peek: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_peek_ex: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_write: function (ssl: PSSL; const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_write_ex: function (s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_write_early_data: function (s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_callback_ctrl: function (v1: PSSL; v2: TOpenSSL_C_INT; v3: SSL_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl = nil;
  SSL_ctrl: function (ssl: PSSL; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl = nil;
  SSL_CTX_ctrl: function (ctx: PSSL_CTX; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl = nil;
  SSL_CTX_callback_ctrl: function (v1: PSSL_CTX; v2: TOpenSSL_C_INT; v3: SSL_CTX_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl = nil;
  SSL_get_early_data_status: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_error: function (const s: PSSL; ret_code: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_version: function (const s: PSSL): PAnsiChar; cdecl = nil;
  SSL_CTX_set_ssl_version: function (ctx: PSSL_CTX; const meth: PSSL_METHOD): TOpenSSL_C_INT; cdecl = nil;
  TLS_method: function : PSSL_METHOD; cdecl = nil;
  TLS_server_method: function : PSSL_METHOD; cdecl = nil;
  TLS_client_method: function : PSSL_METHOD; cdecl = nil;
  SSL_do_handshake: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_key_update: function (s: PSSL; updatetype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_key_update_type: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_renegotiate: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_renegotiate_abbreviated: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_new_session_ticket: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_shutdown: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_post_handshake_auth: procedure (ctx: PSSL_CTX; val: TOpenSSL_C_INT); cdecl = nil;
  SSL_set_post_handshake_auth: procedure (s: PSSL; val: TOpenSSL_C_INT); cdecl = nil;
  SSL_renegotiate_pending: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_verify_client_post_handshake: function (s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get_ssl_method: function (const ctx: PSSL_CTX): PSSL_METHOD; cdecl = nil;
  SSL_get_ssl_method: function (const s: PSSL): PSSL_METHOD; cdecl = nil;
  SSL_set_ssl_method: function (s: PSSL; const method: PSSL_METHOD): TOpenSSL_C_INT; cdecl = nil;
  SSL_alert_type_string_long: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  SSL_alert_type_string: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  SSL_alert_desc_string_long: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  SSL_alert_desc_string: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  SSL_CTX_set_client_CA_list: procedure (ctx: PSSL_CTX; name_list: PSTACK_OF_X509_NAME); cdecl = nil;
  SSL_add_client_CA: function (ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_add_client_CA: function (ctx: PSSL_CTX; x: PX509): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_connect_state: procedure (s: PSSL); cdecl = nil;
  SSL_set_accept_state: procedure (s: PSSL); cdecl = nil;
  SSL_CIPHER_description: function (cipher: PSSL_CIPHER; buf: PAnsiChar; size_ :TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  SSL_dup: function (ssl: PSSL): PSSL; cdecl = nil;
  SSL_get_certificate: function (const ssl: PSSL): PX509; cdecl = nil;
  SSL_get_privatekey: function (const ssl: PSSL): PEVP_PKEY; cdecl = nil;
  SSL_CTX_get0_certificate: function (const ctx: PSSL_CTX): PX509; cdecl = nil;
  SSL_CTX_get0_privatekey: function (const ctx: PSSL_CTX): PEVP_PKEY; cdecl = nil;
  SSL_CTX_set_quiet_shutdown: procedure (ctx: PSSL_CTX; mode: TOpenSSL_C_INT); cdecl = nil;
  SSL_CTX_get_quiet_shutdown: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_quiet_shutdown: procedure (ssl: PSSL; mode: TOpenSSL_C_INT); cdecl = nil;
  SSL_get_quiet_shutdown: function (const ssl: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_shutdown: procedure (ssl: PSSL; mode: TOpenSSL_C_INT); cdecl = nil;
  SSL_get_shutdown: function (const ssl: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_version: function (const ssl: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_client_version: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_default_verify_paths: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_default_verify_dir: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_default_verify_file: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_load_verify_locations: function (ctx: PSSL_CTX; const CAfile: PAnsiChar; const CApath: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_session: function (const ssl: PSSL): PSSL_SESSION; cdecl = nil;
  SSL_get1_session: function (ssl: PSSL): PSSL_SESSION; cdecl = nil;
  SSL_get_SSL_CTX: function (const ssl: PSSL): PSSL_CTX; cdecl = nil;
  SSL_set_SSL_CTX: function (ssl: PSSL; ctx: PSSL_CTX): PSSL_CTX; cdecl = nil;
  SSL_set_info_callback: procedure (ssl: PSSL; cb: SSL_info_callback); cdecl = nil;
  SSL_get_info_callback: function (const ssl: PSSL): SSL_info_callback; cdecl = nil;
  SSL_get_state: function (const ssl: PSSL): OSSL_HANDSHAKE_STATE; cdecl = nil;
  SSL_set_verify_result: procedure (ssl: PSSL; v: TOpenSSL_C_LONG); cdecl = nil;
  SSL_get_verify_result: function (const ssl: PSSL): TOpenSSL_C_LONG; cdecl = nil;
  SSL_get_client_random: function (const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_get_server_random: function (const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_SESSION_get_master_key: function (const sess: PSSL_SESSION; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_SESSION_set1_master_key: function (sess: PSSL_SESSION; const in_: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get_max_fragment_length: function (const sess: PSSL_SESSION): TOpenSSL_C_UINT8; cdecl = nil;
  SSL_set_ex_data: function (ssl: PSSL; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_ex_data: function (const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  SSL_SESSION_set_ex_data: function (ss: PSSL_SESSION; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get_ex_data: function (const ss: PSSL_SESSION; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  SSL_CTX_set_ex_data: function (ssl: PSSL_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get_ex_data: function (const ssl: PSSL_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  SSL_get_ex_data_X509_STORE_CTX_idx: function : TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_default_read_buffer_len: procedure (ctx: PSSL_CTX; len: TOpenSSL_C_SIZET); cdecl = nil;
  SSL_set_default_read_buffer_len: procedure (s: PSSL; len: TOpenSSL_C_SIZET); cdecl = nil;
  SSL_CTX_set_tmp_dh_callback: procedure (ctx: PSSL_CTX; dh: SSL_CTX_set_tmp_dh_callback_dh); cdecl = nil;
  SSL_set_tmp_dh_callback: procedure (ssl: PSSL; dh: SSL_set_tmp_dh_callback_dh); cdecl = nil;
  SSL_CIPHER_find: function (ssl: PSSL; const ptr: PByte): PSSL_CIPHER; cdecl = nil;
  SSL_CIPHER_get_cipher_nid: function (const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl = nil;
  SSL_CIPHER_get_digest_nid: function (const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_session_ticket_ext: function (s: PSSL; ext_data: Pointer; ext_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_session_ticket_ext_cb: function (s: PSSL; cb: tls_session_ticket_ext_cb_fn; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_not_resumable_session_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_set_not_resumable_session_callback_cb); cdecl = nil;
  SSL_set_not_resumable_session_callback: procedure (ssl: PSSL; cb: SSL_set_not_resumable_session_callback_cb); cdecl = nil;
  SSL_CTX_set_record_padding_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_set_record_padding_callback_cb); cdecl = nil;
  SSL_CTX_set_record_padding_callback_arg: procedure (ctx: PSSL_CTX; arg: Pointer); cdecl = nil;
  SSL_CTX_get_record_padding_callback_arg: function (const ctx: PSSL_CTX): Pointer; cdecl = nil;
  SSL_CTX_set_block_padding: function (ctx: PSSL_CTX; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_record_padding_callback: procedure (ssl: PSSL; cb: SSL_set_record_padding_callback_cb); cdecl = nil;
  SSL_set_record_padding_callback_arg: procedure (ssl: PSSL; arg: Pointer); cdecl = nil;
  SSL_get_record_padding_callback_arg: function (const ssl: PSSL): Pointer; cdecl = nil;
  SSL_set_block_padding: function (ssl: PSSL; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_num_tickets: function (s: PSSL; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_num_tickets: function (const s: PSSL): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_CTX_set_num_tickets: function (ctx: PSSL_CTX; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get_num_tickets: function (const ctx: PSSL_CTX): TOpenSSL_C_SIZET; cdecl = nil;
  SSL_session_reused: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_is_server: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_CONF_CTX_new: function : PSSL_CONF_CTX; cdecl = nil;
  SSL_CONF_CTX_finish: function (cctx: PSSL_CONF_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CONF_CTX_free: procedure (cctx: PSSL_CONF_CTX); cdecl = nil;
  SSL_CONF_CTX_set_flags: function (cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl = nil;
  SSL_CONF_CTX_clear_flags: function (cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl = nil;
  SSL_CONF_CTX_set1_prefix: function (cctx: PSSL_CONF_CTX; const pre: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CONF_cmd: function (cctx: PSSL_CONF_CTX; const cmd: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CONF_cmd_argv: function (cctx: PSSL_CONF_CTX; pargc: POpenSSL_C_INT; pargv: PPPAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CONF_cmd_value_type: function (cctx: PSSL_CONF_CTX; const cmd: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CONF_CTX_set_ssl: procedure (cctx: PSSL_CONF_CTX; ssl: PSSL); cdecl = nil;
  SSL_CONF_CTX_set_ssl_ctx: procedure (cctx: PSSL_CONF_CTX; ctx: PSSL_CTX); cdecl = nil;
  SSL_add_ssl_module: procedure ; cdecl = nil;
  SSL_config: function (s: PSSL; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_config: function (ctx: PSSL_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  DTLSv1_listen: function (s: PSSL; client: PBIO_ADDr): TOpenSSL_C_INT; cdecl = nil;
  SSL_enable_ct: function (s: PSSL; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_enable_ct: function (ctx: PSSL_CTX; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SSL_ct_is_enabled: function (const s: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_ct_is_enabled: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_default_ctlog_list_file: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_ctlog_list_file: function (ctx: PSSL_CTX; const path: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set0_ctlog_store: procedure (ctx: PSSL_CTX; logs: PCTLOG_STORE); cdecl = nil;
  SSL_set_security_level: procedure (s: PSSL; level: TOpenSSL_C_INT); cdecl = nil;
  SSL_set_security_callback: procedure (s: PSSL; cb: SSL_security_callback); cdecl = nil;
  SSL_get_security_callback: function (const s: PSSL): SSL_security_callback; cdecl = nil;
  SSL_set0_security_ex_data: procedure (s: PSSL; ex: Pointer); cdecl = nil;
  SSL_get0_security_ex_data: function (const s: PSSL): Pointer; cdecl = nil;
  SSL_CTX_set_security_level: procedure (ctx: PSSL_CTX; level: TOpenSSL_C_INT); cdecl = nil;
  SSL_CTX_get_security_level: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_get0_security_ex_data: function (const ctx: PSSL_CTX): Pointer; cdecl = nil;
  SSL_CTX_set0_security_ex_data: procedure (ctx: PSSL_CTX; ex: Pointer); cdecl = nil;
  OPENSSL_init_ssl: function (opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl = nil;
  SSL_free_buffers: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_alloc_buffers: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = nil;
  SSL_CTX_set_session_ticket_cb: function (ctx: PSSL_CTX; gen_cb: SSL_CTX_generate_session_ticket_fn; dec_cb: SSL_CTX_decrypt_session_ticket_fn; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_set1_ticket_appdata: function (ss: PSSL_SESSION; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SSL_SESSION_get0_ticket_appdata: function (ss: PSSL_SESSION; data: PPointer; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  DTLS_set_timer_cb: procedure (s: PSSL; cb: DTLS_timer_cb); cdecl = nil;
  SSL_CTX_set_allow_early_data_cb: procedure (ctx: PSSL_CTX; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl = nil;
  SSL_set_allow_early_data_cb: procedure (s: PSSL; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl = nil;
  SSL_get0_peer_certificate: function (const s: PSSL): PX509; cdecl = nil; {introduced 3.3.0 }
  SSL_get1_peer_certificate: function (const s: PSSL): PX509; cdecl = nil; {introduced 3.3.0 }





{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  SSL_CTX_set_mode: function (ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_clear_mode: function (ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_sess_set_cache_size: function (ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_sess_get_cache_size: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set_session_cache_mode: function (ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_get_session_cache_mode: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_clear_num_renegotiations: function (ssl: PSSL): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_total_renegotiations: function (ssl: PSSL): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set_tmp_dh: function (ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set_tmp_ecdh: function (ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set_dh_auto: function (ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set_dh_auto: function (s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set_tmp_dh: function (ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set_tmp_ecdh: function (ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_add_extra_chain_cert: function (ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs: function (ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs_only: function (ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_clear_extra_chain_certs: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set0_chain: function (ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_chain: function (ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_add0_chain_cert: function (ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_add1_chain_cert: function (ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_get0_chain_certs: function (ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_clear_chain_certs: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_build_cert_chain: function (ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_select_current_cert: function (ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set_current_cert: function (ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set0_verify_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_verify_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set0_chain_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_chain_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set0_chain: function (s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_chain: function (s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_add0_chain_cert: function (s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_add1_chain_cert: function (s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get0_chain_certs: function (s: PSSL; px509: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_clear_chain_certs: function (s: PSSL): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_build_cert_chain: function (s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_select_current_cert: function (s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set_current_cert: function (s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set0_verify_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_verify_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set0_chain_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_chain_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get1_groups: function (s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_groups: function (ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_groups_list: function (ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_groups: function (s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_groups_list: function (s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get_shared_group: function (s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_sigalgs: function (ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_sigalgs_list: function (ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_sigalgs: function (s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_sigalgs_list: function (s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs: function (ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs_list: function (ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_client_sigalgs: function (s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_client_sigalgs_list: function (s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get0_certificate_types: function (s: PSSL; clist: PByte): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_CTX_set1_client_certificate_types: function (ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_set1_client_certificate_types: function (s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get_signature_nid: function (s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get_peer_signature_nid: function (s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get_peer_tmp_key: function (s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get_tmp_key: function (s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get0_raw_cipherlist: function (s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get0_ec_point_formats: function (s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  SSL_get_app_data: function (const ssl: PSSL): Pointer; cdecl = nil; {removed 1.0.0}
  SSL_set_app_data: function (ssl: PSSL; data: Pointer): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  SSLeay_add_ssl_algorithms: function : TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  SSL_load_error_strings: procedure ; cdecl = nil; {removed 1.1.0}
  SSL_get_peer_certificate: function (const s: PSSL): PX509; cdecl = nil; {removed 3.0.0}
  SSL_library_init: function : TOpenSSL_C_INT; cdecl = nil; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  SSL_CTX_set_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_clear_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_sess_set_cache_size_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_sess_get_cache_size_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_session_cache_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_session_cache_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_clear_num_renegotiations_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_total_renegotiations_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_tmp_dh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_tmp_ecdh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_dh_auto_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_dh_auto_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_tmp_dh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_tmp_ecdh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_add_extra_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs_only_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_clear_extra_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set0_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_add0_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_add1_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get0_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_clear_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_build_cert_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_select_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set0_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set0_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set0_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_add0_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_add1_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_clear_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_build_cert_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_select_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set0_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set0_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get1_groups_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_groups_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_groups_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_groups_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_groups_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_shared_group_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_client_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_client_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_certificate_types_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_client_certificate_types_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_client_certificate_types_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_signature_nid_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_peer_signature_nid_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_peer_tmp_key_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_tmp_key_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_raw_cipherlist_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_ec_point_formats_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_clear_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_clear_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_stateless_cookie_generate_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_stateless_cookie_verify_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_psk_find_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_psk_find_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_psk_use_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_psk_use_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_keylog_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_keylog_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_app_data_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_app_data_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_in_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_in_before_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_is_init_finished_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSLeay_add_ssl_algorithms_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set1_cert_store_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_pending_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_standard_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_cipher_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_protocol_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_kx_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_auth_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_handshake_digest_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_is_aead_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_has_pending_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set0_rbio_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set0_wbio_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_ciphersuites_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_ciphersuites_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_use_serverinfo_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_load_error_strings_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSL_SESSION_get_protocol_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set_protocol_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_hostname_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_hostname_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_alpn_selected_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_alpn_selected_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_has_ticket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_ticket_lifetime_hint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_ticket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_is_resumable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_id_context_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_print_keylog_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_peer_certificate_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  SSL_CTX_set_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_is_dtls_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set1_host_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_add1_host_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_peername_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_hostflags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_enable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_mtype_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_enable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_tlsa_add_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_dane_authority_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_dane_tlsa_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_dane_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_clear_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_clear_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_client_hello_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_isv2_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_legacy_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_random_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_session_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_ciphers_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_compression_methods_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get1_extensions_present_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_ext_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_waiting_for_async_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_all_async_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_changed_async_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_stateless_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_read_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_read_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_peek_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_write_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_write_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_early_data_status_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  TLS_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  TLS_server_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  TLS_client_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_key_update_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_key_update_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_new_session_ticket_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  SSL_CTX_set_post_handshake_auth_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_post_handshake_auth_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_verify_client_post_handshake_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_library_init_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSL_client_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_verify_dir_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_verify_file_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_state_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_client_random_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_server_random_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_master_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_master_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_max_fragment_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_read_buffer_len_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_default_read_buffer_len_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_cipher_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_digest_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_not_resumable_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_not_resumable_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_record_padding_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_block_padding_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_record_padding_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_block_padding_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_session_reused_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_add_ssl_module_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_config_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_config_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DTLSv1_listen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_enable_ct_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_enable_ct_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_ct_is_enabled_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_ct_is_enabled_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_ctlog_list_file_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_ctlog_list_file_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set0_ctlog_store_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_security_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_security_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_security_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_security_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_security_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_init_ssl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_free_buffers_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_alloc_buffers_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_session_ticket_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_ticket_appdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_ticket_appdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DTLS_set_timer_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_allow_early_data_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_allow_early_data_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSLv2_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv2_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv2_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv3_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv3_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv3_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv23_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv23_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv23_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_1_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_1_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_1_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_2_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_2_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_2_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSL_get0_peer_certificate_introduced = ((((((byte(3) shl 8) or byte(3)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.3.0}
  SSL_get1_peer_certificate_introduced = ((((((byte(3) shl 8) or byte(3)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.3.0}


implementation

//#   define SSL_get_peer_certificate SSL_get1_peer_certificate

uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  SSLv2_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv2_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv2_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv3_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv3_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv3_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv23_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv23_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv23_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_1_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_1_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_1_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_2_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_2_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_2_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}


function IsOpenSSL_SSLv2_Available : Boolean;
  begin
    {$if declared(SSLv2_method)}
    Result := Assigned(SSLv2_method) and
      Assigned(SSLv2_server_method) and
      Assigned(SSLv2_client_method);
    {$ELSE}
      Result := false;
    {$ifend}
  end;

  function IsOpenSSL_SSLv3_Available : Boolean;
  begin
    {$if declared(SSLv3_method)}
    Result := Assigned(SSLv3_method) and
      Assigned(SSLv3_server_method) and
      Assigned(SSLv3_client_method);
    {$ELSE}
      Result := true;
    {$ifend}
  end;

  function IsOpenSSL_SSLv23_Available : Boolean;
  begin
    {$if declared(SSLv23_method)}
    Result := Assigned(SSLv23_method) and
      Assigned(SSLv23_server_method) and
      Assigned(SSLv23_client_method);
  {$ELSE}
    Result := false;
    {$ifend}
  end;

  function IsOpenSSL_TLSv1_0_Available : Boolean;
  begin
    {$if declared(TLSv1_method)}
    Result := Assigned(TLSv1_method) and
      Assigned(TLSv1_server_method) and
      Assigned(TLSv1_client_method);
    {$ELSE}
    Result := true;
    {$ifend}
  end;

  function IsOpenSSL_TLSv1_1_Available : Boolean;
  begin
    {$if declared(TLSv1_1_method)}
    Result := Assigned(TLSv1_1_method) and
      Assigned(TLSv1_1_server_method) and
      Assigned(TLSv1_1_client_method);
    {$ELSE}
    Result := true;
    {$ifend}
  end;

  function IsOpenSSL_TLSv1_2_Available : Boolean;
  begin
    {$if declared(TLSv1_2_method)}
     Result := Assigned(TLSv1_2_method) and
      Assigned(TLSv1_2_server_method) and
      Assigned(TLSv1_2_client_method);
     {$ELSE}
     Result := true;
     {$ifend}
  end;



function HasTLS_method: boolean;
begin
  Result := (GetIOpenSSL = nil) or (TLS_method_introduced <= GetIOpenSSL.GetOpenSSLVersion);
end;


//# define SSL_CTX_set_min_proto_version(ctx, version)       SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
function SSL_CTX_set_min_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, nil);
end;

//# define SSL_CTX_set_max_proto_version(ctx, version)       SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
function SSL_CTX_set_max_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, nil);
end;

//# define SSL_CTX_get_min_proto_version(ctx)                SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)
function SSL_CTX_get_min_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, nil);
end;

//# define SSL_CTX_get_max_proto_version(ctx)                SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)
function SSL_CTX_get_max_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, nil);
end;

//# define SSL_set_min_proto_version(s, version)             SSL_ctrl(s, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
function SSL_set_min_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_MIN_PROTO_VERSION, version, nil);
end;

//# define SSL_set_max_proto_version(s, version)             SSL_ctrl(s, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
function SSL_set_max_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_MAX_PROTO_VERSION, version, nil);
end;

//# define SSL_get_min_proto_version(s)                      SSL_ctrl(s, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)
function SSL_get_min_proto_version(s: PSSL): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, nil);
end;

//# define SSL_get_max_proto_version(s)                      SSL_ctrl(s, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)
function SSL_get_max_proto_version(s: PSSL): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, nil);
end;

type
  PSTACK_OF_SSL_CIPHER = pointer;
  Plash_of_SSL_SESSION = pointer;
  SSL_CTX_stats = record
    sess_connect: TOpenSSL_C_INT;  // SSL new conn - started
    sess_connect_renegotiate: TOpenSSL_C_INT;  // SSL reneg - requested
    sess_connect_good: TOpenSSL_C_INT; // SSL new conne/reneg - finished
    sess_accept: TOpenSSL_C_INT;    // SSL new accept - started
    sess_accept_renegotiate: TOpenSSL_C_INT; // SSL reneg - requested
    sess_accept_good: TOpenSSL_C_INT;  // SSL accept/reneg - finished
    sess_miss: TOpenSSL_C_INT;  // session lookup misses
    sess_timeout: TOpenSSL_C_INT; // reuse attempt on timeouted session
    sess_cache_full: TOpenSSL_C_INT; // session removed due to full cache
    sess_hit: TOpenSSL_C_INT; // session reuse actually done
    sess_cb_hit: TOpenSSL_C_INT; // session-id that was not
                          // in the cache was
                          // passed back via the callback.  This
                          // indicates that the application is
                          // supplying session-id's from other
                          // processes - spooky :-)
  end;
  PSTACK_OF_COMP = pointer;
  PSSL_CTX_info_callback = pointer;
  PCERT = pointer;
  size_t = type integer;
  PGEN_SESSION_CB = pointer;
  PSSL_CTEX_tlsext_servername_callback = pointer;
  Ptlsext_status_cb = pointer;
  Ptlsext_ticket_key_cb = pointer;
  Pssl3_buf_freelist_st = pointer;
  PSRP_CTX = ^SRP_CTX;
  SRP_CTX = record
	//* param for all the callbacks */
	  SRP_cb_arg : Pointer;
	//* set client Hello login callback */
    TLS_ext_srp_username_callback : function(para1 : PSSL; para2 : TOpenSSL_C_INT; para3 : Pointer) : TOpenSSL_C_INT cdecl;
	//int (*TLS_ext_srp_username_callback)(SSL *, int *, void *);
	//* set SRP N/g param callback for verification */
    SRP_verify_param_callback : function(para1 : PSSL; para2 : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*SRP_verify_param_callback)(SSL *, void *);
	//* set SRP client passwd callback */
    SRP_give_srp_client_pwd_callback : function(para1 : PSSL; para2 : Pointer) : PAnsiChar cdecl;
  //	char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *);
    login : PAnsiChar;
   	N, g, s, B, A : PBIGNUM;
   	_a, _b, v : PBIGNUM;
	  info : PAnsiChar;
	  strength : TOpenSSL_C_INT;
    srp_Mask : TOpenSSL_C_ULONG;
	end;
  PSTACK_OF_SRTP_PROTECTION_PROFILE = pointer;

  _PSSL_CTX = ^SSL_CTX;
  SSL_CTX = record
    method: PSSL_METHOD;
    cipher_list: PSTACK_OF_SSL_CIPHER;
    // same as above but sorted for lookup
    cipher_list_by_id: PSTACK_OF_SSL_CIPHER;
    cert_store: PX509_STORE;
    sessions: Plash_of_SSL_SESSION;
    // a set of SSL_SESSIONs
    // Most session-ids that will be cached, default is
    // SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
    session_cache_size: TOpenSSL_C_ULONG;
    session_cache_head: PSSL_SESSION;
    session_cache_tail: PSSL_SESSION;
    // This can have one of 2 values, ored together,
    // SSL_SESS_CACHE_CLIENT,
    // SSL_SESS_CACHE_SERVER,
    // Default is SSL_SESSION_CACHE_SERVER, which means only
    // SSL_accept which cache SSL_SESSIONS.
    session_cache_mode: TOpenSSL_C_INT;
    session_timeout: TOpenSSL_C_LONG;
    // If this callback is not null, it will be called each
    // time a session id is added to the cache.  If this function
    // returns 1, it means that the callback will do a
    // SSL_SESSION_free() when it has finished using it.  Otherwise,
    // on 0, it means the callback has finished with it.
    // If remove_session_cb is not null, it will be called when
    // a session-id is removed from the cache.  After the call,
    // OpenSSL will SSL_SESSION_free() it.
    new_session_cb: function (ssl : PSSL; sess: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
    remove_session_cb: procedure (ctx : PSSL_CTX; sess : PSSL_SESSION); cdecl;
    get_session_cb: function (ssl : PSSL; data : PByte; len: TOpenSSL_C_INT; copy : POpenSSL_C_INT) : PSSL_SESSION; cdecl;
    stats : SSL_CTX_stats;

    references: TOpenSSL_C_INT;
    // if defined, these override the X509_verify_cert() calls
    app_verify_callback: function (_para1 : PX509_STORE_CTX; _para2 : Pointer) : TOpenSSL_C_INT; cdecl;
    app_verify_arg: Pointer;
    // before OpenSSL 0.9.7, 'app_verify_arg' was ignored
    // ('app_verify_callback' was called with just one argument)
    // Default password callback.
    default_passwd_callback: pem_password_cb;
    // Default password callback user data.
    default_passwd_callback_userdata: Pointer;
    // get client cert callback
    client_cert_cb: function (SSL : PSSL; x509 : PPX509; pkey : PPEVP_PKEY) : TOpenSSL_C_INT; cdecl;
    // verify cookie callback
    app_gen_cookie_cb: function (ssl : PSSL; cookie : PByte; cookie_len : TOpenSSL_C_UINT) : TOpenSSL_C_INT; cdecl;
    app_verify_cookie_cb: Pointer;
    ex_data : CRYPTO_EX_DATA;
    rsa_md5 : PEVP_MD; // For SSLv2 - name is 'ssl2-md5'
    md5: PEVP_MD; // For SSLv3/TLSv1 'ssl3-md5'
    sha1: PEVP_MD; // For SSLv3/TLSv1 'ssl3->sha1'
    extra_certs: PSTACK_OF_X509;
    comp_methods: PSTACK_OF_COMP; // stack of SSL_COMP, SSLv3/TLSv1
    // Default values used when no per-SSL value is defined follow
    info_callback: PSSL_CTX_info_callback; // used if SSL's info_callback is NULL
    // what we put in client cert requests
    client_CA : PSTACK_OF_X509_NAME;
    // Default values to use in SSL structures follow (these are copied by SSL_new)
    options : TOpenSSL_C_ULONG;
    mode : TOpenSSL_C_ULONG;
    max_cert_list : TOpenSSL_C_LONG;
    cert : PCERT;
    read_ahead : TOpenSSL_C_INT;
    // callback that allows applications to peek at protocol messages
    msg_callback : procedure (write_p, version, content_type : TOpenSSL_C_INT; const buf : Pointer; len : size_t; ssl : PSSL; arg : Pointer); cdecl;
    msg_callback_arg : Pointer;
    verify_mode : TOpenSSL_C_INT;
    sid_ctx_length : TOpenSSL_C_UINT;
    sid_ctx : array[0..SSL_MAX_SID_CTX_LENGTH - 1] of AnsiChar;
    default_verify_callback : function(ok : TOpenSSL_C_INT; ctx : PX509_STORE_CTX) : TOpenSSL_C_INT; cdecl; // called 'verify_callback' in the SSL
    // Default generate session ID callback.
    generate_session_id : PGEN_SESSION_CB;
    param : PX509_VERIFY_PARAM;
    {$IFDEF OMIT_THIS}
    purpose : TOpenSSL_C_INT;  // Purpose setting
    trust : TOpenSSL_C_INT;    // Trust setting
    {$ENDIF}

    quiet_shutdown : TOpenSSL_C_INT;
	//* Maximum amount of data to send in one fragment.
	// * actual record size can be more than this due to
	// * padding and MAC overheads.
	// */
	  max_send_fragment : TOpenSSL_C_UINT;
    {$IFNDEF OPENSSL_ENGINE}
	///* Engine to pass requests for client certs to
	// */
	  client_cert_engine : PENGINE;
    {$ENDIF}
    {$IFNDEF OPENSSL_NO_TLSEXT}
//* TLS extensions servername callback */
    tlsext_servername_callback : PSSL_CTEX_tlsext_servername_callback;
    tlsext_servername_arg : Pointer;
    //* RFC 4507 session ticket keys */
    tlsext_tick_key_name : array [0..(16-1)] of AnsiChar;
    tlsext_tick_hmac_key : array [0..(16-1)] of AnsiChar;
    tlsext_tick_aes_key : array [0..(16-1)] of AnsiChar;
	//* Callback to support customisation of ticket key setting */
 //	int (*tlsext_ticket_key_cb)(SSL *ssl,
 //					unsigned char *name, unsigned char *iv,
 //					EVP_CIPHER_CTX *ectx,
 //					HMAC_CTX *hctx, int enc);
    tlsext_ticket_key_cb : Ptlsext_ticket_key_cb;
	//* certificate status request info */
	//* Callback for status request */
	//int (*tlsext_status_cb)(SSL *ssl, void *arg);
    tlsext_status_cb : Ptlsext_status_cb;
	  tlsext_status_arg : Pointer;
    {$ENDIF}
	//* draft-rescorla-tls-opaque-prf-input-00.txt information */
     tlsext_opaque_prf_input_callback : function(para1 : PSSL; peerinput : Pointer; len : size_t; arg : Pointer ) : TOpenSSL_C_INT cdecl;
	//int (*tlsext_opaque_prf_input_callback)(SSL *, void *peerinput, size_t len, void *arg);
     tlsext_opaque_prf_input_callback_arg : Pointer;

{$ifndef OPENSSL_NO_PSK}
	   psk_identity_hint : PAnsiChar;
     psk_client_callback : function (ssl : PSSL; hint : PAnsiChar;
       identity : PAnsiChar; max_identity_len : TOpenSSL_C_UINT;
       psk : PAnsiChar; max_psk_len : TOpenSSL_C_UINT ) : TOpenSSL_C_UINT cdecl;
 //	unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
//		unsigned int max_identity_len, unsigned char *psk,
//		unsigned int max_psk_len);
     psk_server_callback : function (ssl : PSSL; identity, psk : PAnsiChar; max_psk_len : TOpenSSL_C_UINT) : TOpenSSL_C_UINT cdecl;
//	unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
//		unsigned char *psk, unsigned int max_psk_len);
{$endif}

{$ifndef OPENSSL_NO_BUF_FREELISTS}
	  freelist_max_len : TOpenSSL_C_UINT;
	  wbuf_freelist : Pssl3_buf_freelist_st;
	  rbuf_freelist : Pssl3_buf_freelist_st;
{$endif}
{$ifndef OPENSSL_NO_SRP}
	  srp_ctx : SRP_CTX; //* ctx for SRP authentication */
{$endif}

{$ifndef OPENSSL_NO_TLSEXT}
//# ifndef OPENSSL_NO_NEXTPROTONEG
	//* Next protocol negotiation information */
	//* (for experimental NPN extension). */

	//* For a server, this contains a callback function by which the set of
	// * advertised protocols can be provided. */
    next_protos_advertised_cb : function(s : PSSL; out but : PAnsiChar;
     out len : TOpenSSL_C_UINT; arg : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*next_protos_advertised_cb)(SSL *s, const unsigned char **buf,
//			                 unsigned int *len, void *arg);
	  next_protos_advertised_cb_arg : Pointer;
	//* For a client, this contains a callback function that selects the
	// * next protocol from the list provided by the server. */
    next_proto_select_cb : function(s : PSSL; out _out : PAnsiChar;
      outlen : PAnsiChar;
      _in : PAnsiChar;
      inlen : TOpenSSL_C_UINT;
      arg : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*next_proto_select_cb)(SSL *s, unsigned char **out,
//				    unsigned char *outlen,
//				    const unsigned char *in,
//				    unsigned int inlen,
//				    void *arg);
	  next_proto_select_cb_arg : Pointer;
//# endif
        //* SRTP profiles we are willing to do from RFC 5764 */
      srtp_profiles : PSTACK_OF_SRTP_PROTECTION_PROFILE;
{$endif}
  end;

const
  SSL_CTRL_OPTIONS = 32;
  SSL_CTRL_CLEAR_OPTIONS = 77;


const
  SSL_MAX_KRB5_PRINCIPAL_LENGTH = 256;

type
   PSESS_CERT = pointer;
  _PSSL_SESSION = ^_SSL_SESSION;
  _SSL_SESSION = record
    ssl_version : TOpenSSL_C_INT; // what ssl version session info is being kept in here?
    // only really used in SSLv2
    key_arg_length: TOpenSSL_C_UINT;
    key_arg: Array[0..SSL_MAX_KEY_ARG_LENGTH-1] of Byte;
    master_key_length: TOpenSSL_C_INT;
    master_key: Array[0..SSL_MAX_MASTER_KEY_LENGTH-1] of Byte;
    // session_id - valid?
    session_id_length: TOpenSSL_C_UINT;
    session_id: Array[0..SSL_MAX_SSL_SESSION_ID_LENGTH-1] of Byte;
    // this is used to determine whether the session is being reused in
    // the appropriate context. It is up to the application to set this,
    // via SSL_new
    sid_ctx_length: TOpenSSL_C_UINT;
    sid_ctx: array[0..SSL_MAX_SID_CTX_LENGTH-1] of Byte;
    {$IFNDEF OPENSSL_NO_KRB5}
    krb5_client_princ_len: TOpenSSL_C_UINT;
    krb5_client_princ: array[0..SSL_MAX_KRB5_PRINCIPAL_LENGTH-1] of Byte;
    {$ENDIF}
{$ifndef OPENSSL_NO_PSK}
	  psk_identity_hint : PAnsiChar;
	  psk_identity : PAnsiChar;
{$endif}
    not_resumable: TOpenSSL_C_INT;
    // The cert is the certificate used to establish this connection
    sess_cert :  PSESS_CERT;

	//* This is the cert for the other end.
	// * On clients, it will be the same as sess_cert->peer_key->x509
	// * (the latter is not enough as sess_cert is not retained
	// * in the external representation of sessions, see ssl_asn1.c). */
	  peer : PX509;
	//* when app_verify_callback accepts a session where the peer's certificate
	// * is not ok, we must remember the error for session reuse: */
	  verify_result : TOpenSSL_C_LONG; //* only for servers */
	  references : TOpenSSL_C_INT;
	  timeout : TOpenSSL_C_LONG;
	  time : TOpenSSL_C_LONG;
	  compress_meth : TOpenSSL_C_UINT;	//* Need to lookup the method */

	  cipher : PSSL_CIPHER;
	  cipher_id : TOpenSSL_C_ULONG;	//* when ASN.1 loaded, this
					// * needs to be used to load
					// * the 'cipher' structure */
    ciphers : PSTACK_OF_SSL_CIPHER; //* shared ciphers? */
    ex_data : CRYPTO_EX_DATA; // application specific data */
	//* These are used to make removal of session-ids more
	// * efficient and to implement a maximum cache size. */
	  prev, next : PSSL_SESSION;

    {$IFNDEF OPENSSL_NO_TLSEXT}
    tlsext_hostname : PAnsiChar;
      {$IFDEF OPENSSL_NO_EC}
	  tlsext_ecpointformatlist_length : size_t;
	  tlsext_ecpointformatlist : PAnsiChar; //* peer's list */
	  tlsext_ellipticcurvelist_length : size_t;
	  tlsext_ellipticcurvelist : PAnsiChar; //* peer's list */
      {$ENDIF} //* OPENSSL_NO_EC */

 //* RFC4507 info */
    tlsext_tick : PAnsiChar;//* Session ticket */
    tlsext_ticklen : size_t;//* Session ticket length */
    tlsext_tick_lifetime_hint : TOpenSSL_C_LONG;//* Session lifetime hint in seconds */
    {$ENDIF}
{$ifndef OPENSSL_NO_SRP}
	  srp_username : PAnsiChar;
{$endif}
  end;



threadvar SelectedMethod: TOpenSSL_Version;

procedure OpenSSL_SetMethod(aMethod: TOpenSSL_Version);
begin
  SelectedMethod := aMethod;
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function SSL_get_peer_certificate(const s: PSSL): PX509;

begin
  Result := SSL_get1_peer_certificate(s);
end;


//# define SSL_CTX_set_mode(ctx,op)      SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)


function SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, nil);
end;

//# define SSL_CTX_clear_mode(ctx,op)   SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)


function SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, op, nil);
end;

//# define SSL_CTX_sess_set_cache_size(ctx,t)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)


function SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, t, nil);
end;

//# define SSL_CTX_sess_get_cache_size(ctx)           SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL)


function SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_SIZE, 0, nil);
end;

//# define SSL_CTX_set_session_cache_mode(ctx,m)      SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)


function SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, m, nil);
end;

//# define SSL_CTX_get_session_cache_mode(ctx)        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL)


function SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, nil);
end;

//# define SSL_num_renegotiations(ssl)                       SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)


function SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_total_renegotiations(ssl)                     SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)


function SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_CTX_set_tmp_dh(ctx,dh)                        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_CTX_set_tmp_ecdh(ctx,ecdh)                    SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_set_dh_auto(ctx, onoff)                   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_dh_auto(s, onoff)                         SSL_ctrl(s,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_tmp_dh(ssl,dh)                            SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_set_tmp_ecdh(ssl,ecdh)                        SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_add_extra_chain_cert(ctx,x509)            SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))


function SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_get_extra_chain_certs(ctx,px509)          SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)


function SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_get_extra_chain_certs_only(ctx,px509)     SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)


function SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 1, px509);
end;

//# define SSL_CTX_clear_extra_chain_certs(ctx)              SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)


function SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0, nil);
end;

//# define SSL_CTX_set0_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)(sk))


function SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_CTX_set1_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)(sk))


function SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_CTX_add0_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_add1_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_CTX_get0_chain_certs(ctx,px509)               SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_clear_chain_certs(ctx)                    SSL_CTX_set0_chain(ctx,NULL)


function SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_set0_chain(ctx, nil);
end;

//# define SSL_CTX_build_cert_chain(ctx, flags)              SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_CTX_select_current_cert(ctx,x509)             SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_CTX_set_current_cert(ctx, op)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_CTX_set0_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_CTX_set0_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,0,(char *)(sk))


function SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_set1_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,1,(char *)(sk))


function SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_add0_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_add1_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_get0_chain_certs(s,px509)                     SSL_ctrl(s,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_clear_chain_certs(s)                          SSL_set0_chain(s,NULL)


function SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG;

begin
  Result := SSL_set0_chain(s, nil);
end;

//# define SSL_build_cert_chain(s, flags)                    SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_select_current_cert(s,x509)                   SSL_ctrl(s,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_set_current_cert(s,op)                        SSL_ctrl(s,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_set0_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_set1_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_set1_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_get1_groups(s, glist)                         SSL_ctrl(s,SSL_CTRL_GET_GROUPS,0,(TOpenSSL_C_INT*)(glist))


function SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_GROUPS, 0, glist);
end;

//# define SSL_CTX_set1_groups(ctx, glist, glistlen)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_CTX_set1_groups_list(ctx, s)                  SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(s))


function SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, s);
end;

//# define SSL_set1_groups(s, glist, glistlen)               SSL_ctrl(s,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_set1_groups_list(s, str)                      SSL_ctrl(s,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(str))


function SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS_LIST, 0, str);
end;

//# define SSL_get_shared_group(s, n)                        SSL_ctrl(s,SSL_CTRL_GET_SHARED_GROUP,n,NULL)


function SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SHARED_GROUP, n, nil);
end;

//# define SSL_CTX_set1_sigalgs(ctx, slist, slistlen)        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_sigalgs_list(ctx, s)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(s))


function SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_sigalgs(s, slist, slistlen)              SSL_ctrl(s,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_sigalgs_list(s, str)                     SSL_ctrl(s,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(str))


function SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS_LIST, 0, str);
end;

//# define SSL_CTX_set1_client_sigalgs(ctx, slist, slistlen) SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_client_sigalgs_list(ctx, s)          SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(s))


function SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_client_sigalgs(s, slist, slistlen)       SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_client_sigalgs_list(s, str)              SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(str))


function SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, str);
end;

//# define SSL_get0_certificate_types(s, clist)              SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)(clist))


function SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, clist);
end;

//# define SSL_CTX_set1_client_certificate_types(ctx, clist, clistlen)   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen, (char *)(clist))


function SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_set1_client_certificate_types(s, clist, clistlen)         SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)(clist))


function SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_get_signature_nid(s, pn)                      SSL_ctrl(s,SSL_CTRL_GET_SIGNATURE_NID,0,pn)


function SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_signature_nid(s, pn)                 SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn)


function SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_tmp_key(s, pk)                       SSL_ctrl(s,SSL_CTRL_GET_PEER_TMP_KEY,0,pk)


function SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_TMP_KEY, 0, pk);
end;

//# define SSL_get_tmp_key(s, pk)                            SSL_ctrl(s,SSL_CTRL_GET_TMP_KEY,0,pk)


function SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_TMP_KEY, 0, pk);
end;

//# define SSL_get0_raw_cipherlist(s, plst)                  SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,plst)


function SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_RAW_CIPHERLIST, 0, plst);
end;

//# define SSL_get0_ec_point_formats(s, plst)                SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,plst)


function SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_EC_POINT_FORMATS, 0, plst);
end;


function SSL_get_app_data(const ssl: PSSL): Pointer;

begin
  Result := SSL_get_ex_data(ssl,0);
end;



procedure SSL_load_error_strings;
 
begin
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS,nil); 
end;



function SSL_library_init: TOpenSSL_C_INT;

begin
  Result := OPENSSL_init_ssl(0, nil);
end;



function SSLeay_add_ssl_algorithms: TOpenSSL_C_INT;

begin
  Result := SSL_library_init;
end;



function SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT;

begin
  Result := SSL_set_ex_data(ssl,0,data);
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_SSL_get_peer_certificate(const s: PSSL): PX509; cdecl;

begin
  Result := SSL_get1_peer_certificate(s);
end;


//# define SSL_CTX_set_mode(ctx,op)      SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)


function COMPAT_SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, nil);
end;

//# define SSL_CTX_clear_mode(ctx,op)   SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)


function COMPAT_SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, op, nil);
end;

//# define SSL_CTX_sess_set_cache_size(ctx,t)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)


function COMPAT_SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, t, nil);
end;

//# define SSL_CTX_sess_get_cache_size(ctx)           SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL)


function COMPAT_SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_SIZE, 0, nil);
end;

//# define SSL_CTX_set_session_cache_mode(ctx,m)      SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)


function COMPAT_SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, m, nil);
end;

//# define SSL_CTX_get_session_cache_mode(ctx)        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL)


function COMPAT_SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, nil);
end;

//# define SSL_num_renegotiations(ssl)                       SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)


function COMPAT_SSL_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_GET_NUM_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_clear_num_renegotiations(ssl)                 SSL_ctrl((ssl),SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL)


function COMPAT_SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_total_renegotiations(ssl)                     SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)


function COMPAT_SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_CTX_set_tmp_dh(ctx,dh)                        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function COMPAT_SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_CTX_set_tmp_ecdh(ctx,ecdh)                    SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function COMPAT_SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_set_dh_auto(ctx, onoff)                   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function COMPAT_SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_dh_auto(s, onoff)                         SSL_ctrl(s,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function COMPAT_SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_tmp_dh(ssl,dh)                            SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function COMPAT_SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_set_tmp_ecdh(ssl,ecdh)                        SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function COMPAT_SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_add_extra_chain_cert(ctx,x509)            SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))


function COMPAT_SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_get_extra_chain_certs(ctx,px509)          SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)


function COMPAT_SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_get_extra_chain_certs_only(ctx,px509)     SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)


function COMPAT_SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 1, px509);
end;

//# define SSL_CTX_clear_extra_chain_certs(ctx)              SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)


function COMPAT_SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0, nil);
end;

//# define SSL_CTX_set0_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)(sk))


function COMPAT_SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_CTX_set1_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)(sk))


function COMPAT_SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_CTX_add0_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function COMPAT_SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_add1_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function COMPAT_SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_CTX_get0_chain_certs(ctx,px509)               SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function COMPAT_SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_clear_chain_certs(ctx)                    SSL_CTX_set0_chain(ctx,NULL)


function COMPAT_SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_set0_chain(ctx, nil);
end;

//# define SSL_CTX_build_cert_chain(ctx, flags)              SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function COMPAT_SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_CTX_select_current_cert(ctx,x509)             SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function COMPAT_SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_CTX_set_current_cert(ctx, op)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function COMPAT_SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_CTX_set0_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_CTX_set0_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,0,(char *)(sk))


function COMPAT_SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_set1_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,1,(char *)(sk))


function COMPAT_SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_add0_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function COMPAT_SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_add1_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function COMPAT_SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_get0_chain_certs(s,px509)                     SSL_ctrl(s,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function COMPAT_SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_clear_chain_certs(s)                          SSL_set0_chain(s,NULL)


function COMPAT_SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_set0_chain(s, nil);
end;

//# define SSL_build_cert_chain(s, flags)                    SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function COMPAT_SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_select_current_cert(s,x509)                   SSL_ctrl(s,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function COMPAT_SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_set_current_cert(s,op)                        SSL_ctrl(s,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function COMPAT_SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_set0_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_set1_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_set1_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_get1_groups(s, glist)                         SSL_ctrl(s,SSL_CTRL_GET_GROUPS,0,(TOpenSSL_C_INT*)(glist))


function COMPAT_SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_GROUPS, 0, glist);
end;

//# define SSL_CTX_set1_groups(ctx, glist, glistlen)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function COMPAT_SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_CTX_set1_groups_list(ctx, s)                  SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(s))


function COMPAT_SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, s);
end;

//# define SSL_set1_groups(s, glist, glistlen)               SSL_ctrl(s,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function COMPAT_SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_set1_groups_list(s, str)                      SSL_ctrl(s,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(str))


function COMPAT_SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS_LIST, 0, str);
end;

//# define SSL_get_shared_group(s, n)                        SSL_ctrl(s,SSL_CTRL_GET_SHARED_GROUP,n,NULL)


function COMPAT_SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SHARED_GROUP, n, nil);
end;

//# define SSL_CTX_set1_sigalgs(ctx, slist, slistlen)        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_sigalgs_list(ctx, s)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(s))


function COMPAT_SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_sigalgs(s, slist, slistlen)              SSL_ctrl(s,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_sigalgs_list(s, str)                     SSL_ctrl(s,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(str))


function COMPAT_SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS_LIST, 0, str);
end;

//# define SSL_CTX_set1_client_sigalgs(ctx, slist, slistlen) SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_client_sigalgs_list(ctx, s)          SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(s))


function COMPAT_SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_client_sigalgs(s, slist, slistlen)       SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_client_sigalgs_list(s, str)              SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(str))


function COMPAT_SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, str);
end;

//# define SSL_get0_certificate_types(s, clist)              SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)(clist))


function COMPAT_SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, clist);
end;

//# define SSL_CTX_set1_client_certificate_types(ctx, clist, clistlen)   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen, (char *)(clist))


function COMPAT_SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_set1_client_certificate_types(s, clist, clistlen)         SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)(clist))


function COMPAT_SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_get_signature_nid(s, pn)                      SSL_ctrl(s,SSL_CTRL_GET_SIGNATURE_NID,0,pn)


function COMPAT_SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_signature_nid(s, pn)                 SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn)


function COMPAT_SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_tmp_key(s, pk)                       SSL_ctrl(s,SSL_CTRL_GET_PEER_TMP_KEY,0,pk)


function COMPAT_SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_TMP_KEY, 0, pk);
end;

//# define SSL_get_tmp_key(s, pk)                            SSL_ctrl(s,SSL_CTRL_GET_TMP_KEY,0,pk)


function COMPAT_SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_TMP_KEY, 0, pk);
end;

//# define SSL_get0_raw_cipherlist(s, plst)                  SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,plst)


function COMPAT_SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_RAW_CIPHERLIST, 0, plst);
end;

//# define SSL_get0_ec_point_formats(s, plst)                SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,plst)


function COMPAT_SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_EC_POINT_FORMATS, 0, plst);
end;


function COMPAT_SSL_get_app_data(const ssl: PSSL): Pointer; cdecl;

begin
  Result := SSL_get_ex_data(ssl,0);
end;



procedure COMPAT_SSL_load_error_strings; cdecl;
 
begin
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS,nil); 
end;



function COMPAT_SSL_library_init: TOpenSSL_C_INT; cdecl;

begin
  Result := OPENSSL_init_ssl(0, nil);
end;



function COMPAT_SSLeay_add_ssl_algorithms: TOpenSSL_C_INT; cdecl;

begin
  Result := SSL_library_init;
end;



function COMPAT_SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := SSL_set_ex_data(ssl,0,data);
end;


function COMPAT_SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): pem_password_cb; cdecl;

begin
  Result := _PSSL_CTX(ctx)^.default_passwd_callback;
end;



function COMPAT_SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer; cdecl;

begin
  Result := _PSSL_CTX(ctx)^.default_passwd_callback_userdata;
end;



procedure COMPAT_SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: pem_password_cb); cdecl;

begin
  _PSSL_CTX(ctx)^.default_passwd_callback := cb;
end;



procedure COMPAT_SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer); cdecl;

begin
  _PSSL_CTX(ctx)^.default_passwd_callback_userdata := u;
end;

//* Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value,
// * they cannot be used to clear bits. */



function COMPAT_SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, nil);
end;



function COMPAT_SSL_CTX_clear_options(ctx : PSSL_CTX; op : TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_OPTIONS,op,nil);
end;



function COMPAT_SSL_CTX_get_options(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS,0,nil);
end;



function COMPAT_SSL_CTX_get_cert_store(const ctx: PSSL_CTX): PX509_STORE; cdecl;

begin
  Result :=  _PSSL_CTX(ctx)^.cert_store;
end;


function COMPAT_SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;

begin
  Result := _PSSL_SESSION(s).ssl_version;
end;



function COMPAT_OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;

begin
  if opts and OPENSSL_INIT_LOAD_SSL_STRINGS <> 0 then
    SSL_load_error_strings;
  SSL_library_init;
  Result := OPENSSL_init_crypto(opts,settings);
end;


function COMPAT_TLS_method: PSSL_METHOD; cdecl;

begin
  Result := nil;
  case SelectedMethod of
    sslvSSLv2:
        if Assigned(SSLv2_method) then
          Result := SSLv2_method();

    sslvSSLv23:
          if Assigned(SSLv23_client_method) then
            Result := SSLv23_client_method();

    sslvSSLv3:
        if Assigned(SSLv3_method) then
          Result := SSLv3_method();

    sslvTLSv1:
        if Assigned(TLSv1_method) then
          Result := TLSv1_method();

    sslvTLSv1_1:
        if Assigned(TLSv1_1_method) then
          Result := TLSv1_1_method()
        else
        if Assigned(TLSv1_method) then
          Result := TLSv1_method();

    sslvTLSv1_2:
        if Assigned(TLSv1_2_method) then
          Result := TLSv1_2_method()
        else
        if Assigned(TLSv1_method) then
          Result := TLSv1_method();
  end;
end;



function COMPAT_TLS_server_method: PSSL_METHOD; cdecl;

begin
  Result := nil;
  case SelectedMethod of
    sslvSSLv2:
          if Assigned(SSLv2_server_method) then
            Result := SSLv2_server_method();

    sslvSSLv23:
          if Assigned(SSLv23_server_method) then
            Result := SSLv23_server_method();

    sslvSSLv3:
          if Assigned(SSLv3_server_method) then
            Result := SSLv3_server_method();

    sslvTLSv1:
      if Assigned(TLSv1_server_method) then
        Result := TLSv1_server_method();

    sslvTLSv1_1:
          if Assigned(TLSv1_1_server_method) then
            Result := TLSv1_1_server_method()
          else
          if Assigned(TLSv1_server_method) then
            Result := TLSv1_server_method();

    sslvTLSv1_2:
          if Assigned(TLSv1_2_server_method) then
            Result := TLSv1_2_server_method()
          else
          if Assigned(TLSv1_server_method) then
            Result := TLSv1_server_method();
  end;
end;



function COMPAT_TLS_client_method: PSSL_METHOD; cdecl;

begin
  Result := nil;
  case SelectedMethod of
    sslvSSLv2:
          if Assigned(SSLv2_client_method) then
            Result := SSLv2_client_method();

    sslvSSLv23:
          if Assigned(SSLv23_client_method) then
            Result := SSLv23_client_method();

    sslvSSLv3:
          if Assigned(SSLv3_client_method) then
            Result := SSLv3_client_method();

    sslvTLSv1:
      if Assigned(TLSv1_client_method) then
        Result := TLSv1_client_method();

    sslvTLSv1_1:
          if Assigned(TLSv1_1_client_method) then
            Result := TLSv1_1_client_method()
          else
          if Assigned(TLSv1_client_method) then
            Result := TLSv1_client_method();

    sslvTLSv1_2:
          if Assigned(TLSv1_2_client_method) then
            Result := TLSv1_2_client_method()
          else
          if Assigned(TLSv1_client_method) then
            Result := TLSv1_client_method();
  end;
end;



function COMPAT_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;

begin
  Result := SSL_CTX_use_certificate_file(ctx, file_, SSL_FILETYPE_PEM);
end;



function COMPAT_SSL_new_session_ticket(s: PSSL): TOpenSSL_C_INT; cdecl;

begin
// no op
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_mode');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_clear_mode');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_set_cache_size');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_get_cache_size');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_session_cache_mode');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_session_cache_mode');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_clear_num_renegotiations');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_total_renegotiations');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_tmp_dh');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_tmp_ecdh');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_dh_auto');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_dh_auto');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_tmp_dh');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_tmp_ecdh');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_add_extra_chain_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_extra_chain_certs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_extra_chain_certs_only');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_clear_extra_chain_certs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set0_chain');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_chain');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_add0_chain_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_add1_chain_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_chain_certs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_clear_chain_certs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_build_cert_chain');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_select_current_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_current_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set0_verify_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_verify_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set0_chain_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_chain_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_chain');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_chain');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add0_chain_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add1_chain_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_chain_certs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_clear_chain_certs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_build_cert_chain');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_select_current_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_current_cert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_verify_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_verify_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_chain_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_chain_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get1_groups');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_groups');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_groups_list');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_groups');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_groups_list');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_shared_group');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_sigalgs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_sigalgs_list');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_sigalgs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_sigalgs_list');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_client_sigalgs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_client_sigalgs_list');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_client_sigalgs');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_client_sigalgs_list');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_certificate_types');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_client_certificate_types');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_client_certificate_types');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_signature_nid');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_peer_signature_nid');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_peer_tmp_key');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_tmp_key');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_raw_cipherlist');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_ec_point_formats');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get_options(const ctx: PSSL_CTX): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_options');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_get_options(const s: PSSL): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_options');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_clear_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_clear_options');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_clear_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_clear_options');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_options');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_set_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_options');
end;

procedure ERROR_SSL_CTX_sess_set_new_cb(ctx: PSSL_CTX; new_session_cb: SSL_CTX_sess_new_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_set_new_cb');
end;

function ERROR_SSL_CTX_sess_get_new_cb(ctx: PSSL_CTX): SSL_CTX_sess_new_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_get_new_cb');
end;

procedure ERROR_SSL_CTX_sess_set_remove_cb(ctx: PSSL_CTX; remove_session_cb: SSL_CTX_sess_remove_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_set_remove_cb');
end;

function ERROR_SSL_CTX_sess_get_remove_cb(ctx: PSSL_CTX): SSL_CTX_sess_remove_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_get_remove_cb');
end;

procedure ERROR_SSL_CTX_set_info_callback(ctx: PSSL_CTX; cb: SSL_CTX_info_callback); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_info_callback');
end;

function ERROR_SSL_CTX_get_info_callback(ctx: PSSL_CTX): SSL_CTX_info_callback; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_info_callback');
end;

procedure ERROR_SSL_CTX_set_client_cert_cb(ctx: PSSL_CTX; client_cert_cb: SSL_CTX_client_cert_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_cert_cb');
end;

function ERROR_SSL_CTX_get_client_cert_cb(ctx: PSSL_CTX): SSL_CTX_client_cert_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_client_cert_cb');
end;

function ERROR_SSL_CTX_set_client_cert_engine(ctx: PSSL_CTX; e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_cert_engine');
end;

procedure ERROR_SSL_CTX_set_cookie_generate_cb(ctx: PSSL_CTX; app_gen_cookie_cb: SSL_CTX_cookie_verify_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cookie_generate_cb');
end;

procedure ERROR_SSL_CTX_set_cookie_verify_cb(ctx: PSSL_CTX; app_verify_cookie_cb: SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cookie_verify_cb');
end;

procedure ERROR_SSL_CTX_set_stateless_cookie_generate_cb(ctx: PSSL_CTX; gen_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_stateless_cookie_generate_cb');
end;

procedure ERROR_SSL_CTX_set_stateless_cookie_verify_cb(ctx: PSSL_CTX; verify_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_stateless_cookie_verify_cb');
end;

procedure ERROR_SSL_CTX_set_alpn_select_cb(ctx: PSSL_CTX; cb: SSL_CTX_alpn_select_cb_func; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_alpn_select_cb');
end;

procedure ERROR_SSL_get0_alpn_selected(const ssl: PSSL; const data: PPByte; len: POpenSSL_C_UINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_alpn_selected');
end;

procedure ERROR_SSL_CTX_set_psk_client_callback(ctx: PSSL_CTX; cb: SSL_psk_client_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_client_callback');
end;

procedure ERROR_SSL_set_psk_client_callback(ssl: PSSL; cb: SSL_psk_client_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_client_callback');
end;

procedure ERROR_SSL_CTX_set_psk_server_callback(ctx: PSSL_CTX; cb: SSL_psk_server_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_server_callback');
end;

procedure ERROR_SSL_set_psk_server_callback(ssl: PSSL; cb: SSL_psk_server_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_server_callback');
end;

procedure ERROR_SSL_set_psk_find_session_callback(s: PSSL; cb: SSL_psk_find_session_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_find_session_callback');
end;

procedure ERROR_SSL_CTX_set_psk_find_session_callback(ctx: PSSL_CTX; cb: SSL_psk_find_session_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_find_session_callback');
end;

procedure ERROR_SSL_set_psk_use_session_callback(s: PSSL; cb: SSL_psk_use_session_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_use_session_callback');
end;

procedure ERROR_SSL_CTX_set_psk_use_session_callback(ctx: PSSL_CTX; cb: SSL_psk_use_session_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_use_session_callback');
end;

procedure ERROR_SSL_CTX_set_keylog_callback(ctx: PSSL_CTX; cb: SSL_CTX_keylog_cb_func); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_keylog_callback');
end;

function ERROR_SSL_CTX_get_keylog_callback(const ctx: PSSL_CTX): SSL_CTX_keylog_cb_func; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_keylog_callback');
end;

function ERROR_SSL_CTX_set_max_early_data(ctx: PSSL_CTX; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_max_early_data');
end;

function ERROR_SSL_CTX_get_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_max_early_data');
end;

function ERROR_SSL_set_max_early_data(s: PSSL; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_max_early_data');
end;

function ERROR_SSL_get_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_max_early_data');
end;

function ERROR_SSL_CTX_set_recv_max_early_data(ctx: PSSL_CTX; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_recv_max_early_data');
end;

function ERROR_SSL_CTX_get_recv_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_recv_max_early_data');
end;

function ERROR_SSL_set_recv_max_early_data(s: PSSL; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_recv_max_early_data');
end;

function ERROR_SSL_get_recv_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_recv_max_early_data');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get_app_data(const ssl: PSSL): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_app_data');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_app_data');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_in_init(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_in_init');
end;

function ERROR_SSL_in_before(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_in_before');
end;

function ERROR_SSL_is_init_finished(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_is_init_finished');
end;

function ERROR_SSL_get_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_finished');
end;

function ERROR_SSL_get_peer_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_peer_finished');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSLeay_add_ssl_algorithms: TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSLeay_add_ssl_algorithms');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_BIO_f_ssl: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_ssl');
end;

function ERROR_BIO_new_ssl(ctx: PSSL_CTX; client: TOpenSSL_C_INT): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_ssl');
end;

function ERROR_BIO_new_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_ssl_connect');
end;

function ERROR_BIO_new_buffer_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_buffer_ssl_connect');
end;

function ERROR_BIO_ssl_copy_session_id(to_: PBIO; from: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ssl_copy_session_id');
end;

function ERROR_SSL_CTX_set_cipher_list(v1: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cipher_list');
end;

function ERROR_SSL_CTX_new(const meth: PSSL_METHOD): PSSL_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_new');
end;

function ERROR_SSL_CTX_set_timeout(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_timeout');
end;

function ERROR_SSL_CTX_get_timeout(const ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_timeout');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get_cert_store(const v1: PSSL_CTX): PX509_STORE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_cert_store');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_want(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_want');
end;

function ERROR_SSL_clear(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_clear');
end;

procedure ERROR_BIO_ssl_shutdown(ssl_bio: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ssl_shutdown');
end;

function ERROR_SSL_CTX_up_ref(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_up_ref');
end;

procedure ERROR_SSL_CTX_free(v1: PSSL_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_free');
end;

procedure ERROR_SSL_CTX_set_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cert_store');
end;

procedure ERROR_SSL_CTX_set1_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_cert_store');
end;

procedure ERROR_SSL_CTX_flush_sessions(ctx: PSSL_CTX; tm: TOpenSSL_C_LONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_flush_sessions');
end;

function ERROR_SSL_get_current_cipher(const s: PSSL): PSSL_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_current_cipher');
end;

function ERROR_SSL_get_pending_cipher(const s: PSSL): PSSL_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_pending_cipher');
end;

function ERROR_SSL_CIPHER_get_bits(const c: PSSL_CIPHER; var alg_bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_bits');
end;

function ERROR_SSL_CIPHER_get_version(const c: PSSL_CIPHER): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_version');
end;

function ERROR_SSL_CIPHER_get_name(const c: PSSL_CIPHER): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_name');
end;

function ERROR_SSL_CIPHER_standard_name(const c: PSSL_CIPHER): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_standard_name');
end;

function ERROR_OPENSSL_cipher_name(const rfc_name: PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_cipher_name');
end;

function ERROR_SSL_CIPHER_get_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_id');
end;

function ERROR_SSL_CIPHER_get_protocol_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT16; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_protocol_id');
end;

function ERROR_SSL_CIPHER_get_kx_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_kx_nid');
end;

function ERROR_SSL_CIPHER_get_auth_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_auth_nid');
end;

function ERROR_SSL_CIPHER_get_handshake_digest(const c: PSSL_CIPHER): PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_handshake_digest');
end;

function ERROR_SSL_CIPHER_is_aead(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_is_aead');
end;

function ERROR_SSL_get_fd(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_fd');
end;

function ERROR_SSL_get_rfd(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_rfd');
end;

function ERROR_SSL_get_wfd(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_wfd');
end;

function ERROR_SSL_get_cipher_list(const s: PSSL; n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_cipher_list');
end;

function ERROR_SSL_get_shared_ciphers(const s: PSSL; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_shared_ciphers');
end;

function ERROR_SSL_get_read_ahead(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_read_ahead');
end;

function ERROR_SSL_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_pending');
end;

function ERROR_SSL_has_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_has_pending');
end;

function ERROR_SSL_set_fd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_fd');
end;

function ERROR_SSL_set_rfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_rfd');
end;

function ERROR_SSL_set_wfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_wfd');
end;

procedure ERROR_SSL_set0_rbio(s: PSSL; rbio: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_rbio');
end;

procedure ERROR_SSL_set0_wbio(s: PSSL; wbio: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_wbio');
end;

procedure ERROR_SSL_set_bio(s: PSSL; rbio: PBIO; wbio: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_bio');
end;

function ERROR_SSL_get_rbio(const s: PSSL): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_rbio');
end;

function ERROR_SSL_get_wbio(const s: PSSL): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_wbio');
end;

function ERROR_SSL_set_cipher_list(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_cipher_list');
end;

function ERROR_SSL_CTX_set_ciphersuites(ctx: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ciphersuites');
end;

function ERROR_SSL_set_ciphersuites(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_ciphersuites');
end;

function ERROR_SSL_get_verify_mode(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_mode');
end;

function ERROR_SSL_get_verify_depth(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_depth');
end;

function ERROR_SSL_get_verify_callback(const s: PSSL): SSL_verify_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_callback');
end;

procedure ERROR_SSL_set_read_ahead(s: PSSL; yes: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_read_ahead');
end;

procedure ERROR_SSL_set_verify(s: PSSL; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_verify');
end;

procedure ERROR_SSL_set_verify_depth(s: PSSL; depth: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_verify_depth');
end;

function ERROR_SSL_use_RSAPrivateKey(ssl: PSSL; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_RSAPrivateKey');
end;

function ERROR_SSL_use_RSAPrivateKey_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_RSAPrivateKey_ASN1');
end;

function ERROR_SSL_use_PrivateKey(ssl: PSSL; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_PrivateKey');
end;

function ERROR_SSL_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_PrivateKey_ASN1');
end;

function ERROR_SSL_use_certificate(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate');
end;

function ERROR_SSL_use_certificate_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate_ASN1');
end;

function ERROR_SSL_CTX_use_serverinfo(ctx: PSSL_CTX; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_serverinfo');
end;

function ERROR_SSL_CTX_use_serverinfo_ex(ctx: PSSL_CTX; version: TOpenSSL_C_UINT; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_serverinfo_ex');
end;

function ERROR_SSL_CTX_use_serverinfo_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_serverinfo_file');
end;

function ERROR_SSL_use_RSAPrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_RSAPrivateKey_file');
end;

function ERROR_SSL_use_PrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_PrivateKey_file');
end;

function ERROR_SSL_use_certificate_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate_file');
end;

function ERROR_SSL_CTX_use_RSAPrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_RSAPrivateKey_file');
end;

function ERROR_SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_PrivateKey_file');
end;

function ERROR_SSL_CTX_use_certificate_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate_file');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate_chain_file');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_use_certificate_chain_file(ssl: PSSL; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate_chain_file');
end;

function ERROR_SSL_load_client_CA_file(const file_: PAnsiChar): PSTACK_OF_X509_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_load_client_CA_file');
end;

function ERROR_SSL_add_file_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_file_cert_subjects_to_stack');
end;

function ERROR_SSL_add_dir_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const dir_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_dir_cert_subjects_to_stack');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_SSL_load_error_strings; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_load_error_strings');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_state_string(const s: PSSL): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_state_string');
end;

function ERROR_SSL_rstate_string(const s: PSSL): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_rstate_string');
end;

function ERROR_SSL_state_string_long(const s: PSSL): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_state_string_long');
end;

function ERROR_SSL_rstate_string_long(const s: PSSL): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_rstate_string_long');
end;

function ERROR_SSL_SESSION_get_time(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_time');
end;

function ERROR_SSL_SESSION_set_time(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_time');
end;

function ERROR_SSL_SESSION_get_timeout(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_timeout');
end;

function ERROR_SSL_SESSION_set_timeout(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_timeout');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_protocol_version');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_SESSION_set_protocol_version(s: PSSL_SESSION; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_protocol_version');
end;

function ERROR_SSL_SESSION_get0_hostname(const s: PSSL_SESSION): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_hostname');
end;

function ERROR_SSL_SESSION_set1_hostname(s: PSSL_SESSION; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_hostname');
end;

procedure ERROR_SSL_SESSION_get0_alpn_selected(const s: PSSL_SESSION; const alpn: PPByte; len: POpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_alpn_selected');
end;

function ERROR_SSL_SESSION_set1_alpn_selected(s: PSSL_SESSION; const alpn: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_alpn_selected');
end;

function ERROR_SSL_SESSION_get0_cipher(const s: PSSL_SESSION): PSSL_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_cipher');
end;

function ERROR_SSL_SESSION_set_cipher(s: PSSL_SESSION; const cipher: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_cipher');
end;

function ERROR_SSL_SESSION_has_ticket(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_has_ticket');
end;

function ERROR_SSL_SESSION_get_ticket_lifetime_hint(const s: PSSL_SESSION): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_ticket_lifetime_hint');
end;

procedure ERROR_SSL_SESSION_get0_ticket(const s: PSSL_SESSION; const tick: PPByte; len: POpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_ticket');
end;

function ERROR_SSL_SESSION_get_max_early_data(const s: PSSL_SESSION): TOpenSSL_C_UINT32; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_max_early_data');
end;

function ERROR_SSL_SESSION_set_max_early_data(s: PSSL_SESSION; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_max_early_data');
end;

function ERROR_SSL_copy_session_id(to_: PSSL; const from: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_copy_session_id');
end;

function ERROR_SSL_SESSION_get0_peer(s: PSSL_SESSION): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_peer');
end;

function ERROR_SSL_SESSION_set1_id_context(s: PSSL_SESSION; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_id_context');
end;

function ERROR_SSL_SESSION_set1_id(s: PSSL_SESSION; const sid: PByte; sid_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_id');
end;

function ERROR_SSL_SESSION_is_resumable(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_is_resumable');
end;

function ERROR_SSL_SESSION_new: PSSL_SESSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_new');
end;

function ERROR_SSL_SESSION_dup(src: PSSL_SESSION): PSSL_SESSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_dup');
end;

function ERROR_SSL_SESSION_get_id(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_id');
end;

function ERROR_SSL_SESSION_get0_id_context(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_id_context');
end;

function ERROR_SSL_SESSION_get_compress_id(const s: PSSL_SESSION): TOpenSSL_C_UINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_compress_id');
end;

function ERROR_SSL_SESSION_print(fp: PBIO; const ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_print');
end;

function ERROR_SSL_SESSION_print_keylog(bp: PBIO; const x: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_print_keylog');
end;

function ERROR_SSL_SESSION_up_ref(ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_up_ref');
end;

procedure ERROR_SSL_SESSION_free(ses: PSSL_SESSION); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_free');
end;

function ERROR_SSL_set_session(to_: PSSL; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session');
end;

function ERROR_SSL_CTX_add_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_add_session');
end;

function ERROR_SSL_CTX_remove_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_remove_session');
end;

function ERROR_SSL_CTX_set_generate_session_id(ctx: PSSL_CTX; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_generate_session_id');
end;

function ERROR_SSL_set_generate_session_id(s: PSSL; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_generate_session_id');
end;

function ERROR_SSL_has_matching_session_id(const s: PSSL; const id: PByte; id_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_has_matching_session_id');
end;

function ERROR_d2i_SSL_SESSION(a: PPSSL_SESSION; const pp: PPByte; length: TOpenSSL_C_LONG): PSSL_SESSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_SSL_SESSION');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_get_peer_certificate(const s: PSSL): PX509; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_peer_certificate');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_CTX_get_verify_mode(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_verify_mode');
end;

function ERROR_SSL_CTX_get_verify_depth(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_verify_depth');
end;

function ERROR_SSL_CTX_get_verify_callback(const ctx: PSSL_CTX): SSL_verify_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_verify_callback');
end;

procedure ERROR_SSL_CTX_set_verify(ctx: PSSL_CTX; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_verify');
end;

procedure ERROR_SSL_CTX_set_verify_depth(ctx: PSSL_CTX; depth: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_verify_depth');
end;

procedure ERROR_SSL_CTX_set_cert_verify_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_cert_verify_callback_cb; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cert_verify_callback');
end;

procedure ERROR_SSL_CTX_set_cert_cb(c: PSSL_CTX; cb: SSL_CTX_set_cert_cb_cb; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cert_cb');
end;

function ERROR_SSL_CTX_use_RSAPrivateKey(ctx: PSSL_CTX; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_RSAPrivateKey');
end;

function ERROR_SSL_CTX_use_RSAPrivateKey_ASN1(ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_RSAPrivateKey_ASN1');
end;

function ERROR_SSL_CTX_use_PrivateKey(ctx: PSSL_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_PrivateKey');
end;

function ERROR_SSL_CTX_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_PrivateKey_ASN1');
end;

function ERROR_SSL_CTX_use_certificate(ctx: PSSL_CTX; x: X509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate');
end;

function ERROR_SSL_CTX_use_certificate_ASN1(ctx: PSSL_CTX; len: TOpenSSL_C_INT; const d: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate_ASN1');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: pem_password_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_passwd_cb');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_passwd_cb_userdata');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): pem_password_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_default_passwd_cb');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_default_passwd_cb_userdata');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

procedure ERROR_SSL_set_default_passwd_cb(s: PSSL; cb: pem_password_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_default_passwd_cb');
end;

procedure ERROR_SSL_set_default_passwd_cb_userdata(s: PSSL; u: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_default_passwd_cb_userdata');
end;

function ERROR_SSL_get_default_passwd_cb(s: PSSL): pem_password_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_default_passwd_cb');
end;

function ERROR_SSL_get_default_passwd_cb_userdata(s: PSSL): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_default_passwd_cb_userdata');
end;

function ERROR_SSL_CTX_check_private_key(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_check_private_key');
end;

function ERROR_SSL_check_private_key(const ctx: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_check_private_key');
end;

function ERROR_SSL_CTX_set_session_id_context(ctx: PSSL_CTX; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_session_id_context');
end;

function ERROR_SSL_new(ctx: PSSL_CTX): PSSL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_new');
end;

function ERROR_SSL_up_ref(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_up_ref');
end;

function ERROR_SSL_is_dtls(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_is_dtls');
end;

function ERROR_SSL_set_session_id_context(ssl: PSSL; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session_id_context');
end;

function ERROR_SSL_CTX_set_purpose(ctx: PSSL_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_purpose');
end;

function ERROR_SSL_set_purpose(ssl: PSSL; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_purpose');
end;

function ERROR_SSL_CTX_set_trust(ctx: PSSL_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_trust');
end;

function ERROR_SSL_set_trust(ssl: PSSL; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_trust');
end;

function ERROR_SSL_set1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_host');
end;

function ERROR_SSL_add1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add1_host');
end;

function ERROR_SSL_get0_peername(s: PSSL): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_peername');
end;

procedure ERROR_SSL_set_hostflags(s: PSSL; flags: TOpenSSL_C_UINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_hostflags');
end;

function ERROR_SSL_CTX_dane_enable(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_enable');
end;

function ERROR_SSL_CTX_dane_mtype_set(ctx: PSSL_CTX; const md: PEVP_MD; mtype: TOpenSSL_C_UINT8; ord: TOpenSSL_C_UINT8): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_mtype_set');
end;

function ERROR_SSL_dane_enable(s: PSSL; const basedomain: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_enable');
end;

function ERROR_SSL_dane_tlsa_add(s: PSSL; usage: TOpenSSL_C_UINT8; selector: TOpenSSL_C_UINT8; mtype: TOpenSSL_C_UINT8; const data: PByte; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_tlsa_add');
end;

function ERROR_SSL_get0_dane_authority(s: PSSL; mcert: PPX509; mspki: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_dane_authority');
end;

function ERROR_SSL_get0_dane_tlsa(s: PSSL; usage: POpenSSL_C_UINT8; selector: POpenSSL_C_UINT8; mtype: POpenSSL_C_UINT8; const data: PPByte; dlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_dane_tlsa');
end;

function ERROR_SSL_get0_dane(ssl: PSSL): PSSL_DANE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_dane');
end;

function ERROR_SSL_CTX_dane_set_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_set_flags');
end;

function ERROR_SSL_CTX_dane_clear_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_clear_flags');
end;

function ERROR_SSL_dane_set_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_set_flags');
end;

function ERROR_SSL_dane_clear_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_clear_flags');
end;

function ERROR_SSL_CTX_set1_param(ctx: PSSL_CTX; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_param');
end;

function ERROR_SSL_set1_param(ssl: PSSL; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_param');
end;

function ERROR_SSL_CTX_get0_param(ctx: PSSL_CTX): PX509_VERIFY_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_param');
end;

function ERROR_SSL_get0_param(ssl: PSSL): PX509_VERIFY_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_param');
end;

function ERROR_SSL_CTX_set_srp_username(ctx: PSSL_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_username');
end;

function ERROR_SSL_CTX_set_srp_password(ctx: PSSL_CTX; password: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_password');
end;

function ERROR_SSL_CTX_set_srp_strength(ctx: PSSL_CTX; strength: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_strength');
end;

function ERROR_SSL_CTX_set_srp_client_pwd_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_client_pwd_callback_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_client_pwd_callback');
end;

function ERROR_SSL_CTX_set_srp_verify_param_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_verify_param_callback_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_verify_param_callback');
end;

function ERROR_SSL_CTX_set_srp_username_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_username_callback_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_username_callback');
end;

function ERROR_SSL_CTX_set_srp_cb_arg(ctx: PSSL_CTX; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_cb_arg');
end;

function ERROR_SSL_set_srp_server_param(s: PSSL; const N: PBIGNUm; const g: PBIGNUm; sa: PBIGNUm; v: PBIGNUm; info: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_srp_server_param');
end;

function ERROR_SSL_set_srp_server_param_pw(s: PSSL; const user: PAnsiChar; const pass: PAnsiChar; const grp: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_srp_server_param_pw');
end;

procedure ERROR_SSL_CTX_set_client_hello_cb(c: PSSL_CTX; cb: SSL_client_hello_cb_fn; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_hello_cb');
end;

function ERROR_SSL_client_hello_isv2(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_isv2');
end;

function ERROR_SSL_client_hello_get0_legacy_version(s: PSSL): TOpenSSL_C_UINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_legacy_version');
end;

function ERROR_SSL_client_hello_get0_random(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_random');
end;

function ERROR_SSL_client_hello_get0_session_id(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_session_id');
end;

function ERROR_SSL_client_hello_get0_ciphers(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_ciphers');
end;

function ERROR_SSL_client_hello_get0_compression_methods(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_compression_methods');
end;

function ERROR_SSL_client_hello_get1_extensions_present(s: PSSL; out_: PPOpenSSL_C_INT; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get1_extensions_present');
end;

function ERROR_SSL_client_hello_get0_ext(s: PSSL; type_: TOpenSSL_C_UINT; const out_: PPByte; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_ext');
end;

procedure ERROR_SSL_certs_clear(s: PSSL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_certs_clear');
end;

procedure ERROR_SSL_free(ssl: PSSL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_free');
end;

function ERROR_SSL_waiting_for_async(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_waiting_for_async');
end;

function ERROR_SSL_get_all_async_fds(s: PSSL; fds: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_all_async_fds');
end;

function ERROR_SSL_get_changed_async_fds(s: PSSL; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_changed_async_fds');
end;

function ERROR_SSL_accept(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_accept');
end;

function ERROR_SSL_stateless(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_stateless');
end;

function ERROR_SSL_connect(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_connect');
end;

function ERROR_SSL_read(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_read');
end;

function ERROR_SSL_read_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_read_ex');
end;

function ERROR_SSL_read_early_data(s: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_read_early_data');
end;

function ERROR_SSL_peek(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_peek');
end;

function ERROR_SSL_peek_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_peek_ex');
end;

function ERROR_SSL_write(ssl: PSSL; const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_write');
end;

function ERROR_SSL_write_ex(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_write_ex');
end;

function ERROR_SSL_write_early_data(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_write_early_data');
end;

function ERROR_SSL_callback_ctrl(v1: PSSL; v2: TOpenSSL_C_INT; v3: SSL_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_callback_ctrl');
end;

function ERROR_SSL_ctrl(ssl: PSSL; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ctrl');
end;

function ERROR_SSL_CTX_ctrl(ctx: PSSL_CTX; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_ctrl');
end;

function ERROR_SSL_CTX_callback_ctrl(v1: PSSL_CTX; v2: TOpenSSL_C_INT; v3: SSL_CTX_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_callback_ctrl');
end;

function ERROR_SSL_get_early_data_status(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_early_data_status');
end;

function ERROR_SSL_get_error(const s: PSSL; ret_code: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_error');
end;

function ERROR_SSL_get_version(const s: PSSL): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_version');
end;

function ERROR_SSL_CTX_set_ssl_version(ctx: PSSL_CTX; const meth: PSSL_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ssl_version');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_TLS_method: PSSL_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TLS_method');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_TLS_server_method: PSSL_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TLS_server_method');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_TLS_client_method: PSSL_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TLS_client_method');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_do_handshake(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_do_handshake');
end;

function ERROR_SSL_key_update(s: PSSL; updatetype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_key_update');
end;

function ERROR_SSL_get_key_update_type(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_key_update_type');
end;

function ERROR_SSL_renegotiate(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_renegotiate');
end;

function ERROR_SSL_renegotiate_abbreviated(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_renegotiate_abbreviated');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_new_session_ticket(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_new_session_ticket');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_shutdown(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_shutdown');
end;

procedure ERROR_SSL_CTX_set_post_handshake_auth(ctx: PSSL_CTX; val: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_post_handshake_auth');
end;

procedure ERROR_SSL_set_post_handshake_auth(s: PSSL; val: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_post_handshake_auth');
end;

function ERROR_SSL_renegotiate_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_renegotiate_pending');
end;

function ERROR_SSL_verify_client_post_handshake(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_verify_client_post_handshake');
end;

function ERROR_SSL_CTX_get_ssl_method(const ctx: PSSL_CTX): PSSL_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_ssl_method');
end;

function ERROR_SSL_get_ssl_method(const s: PSSL): PSSL_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_ssl_method');
end;

function ERROR_SSL_set_ssl_method(s: PSSL; const method: PSSL_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_ssl_method');
end;

function ERROR_SSL_alert_type_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_type_string_long');
end;

function ERROR_SSL_alert_type_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_type_string');
end;

function ERROR_SSL_alert_desc_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_desc_string_long');
end;

function ERROR_SSL_alert_desc_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_desc_string');
end;

procedure ERROR_SSL_CTX_set_client_CA_list(ctx: PSSL_CTX; name_list: PSTACK_OF_X509_NAME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_CA_list');
end;

function ERROR_SSL_add_client_CA(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_client_CA');
end;

function ERROR_SSL_CTX_add_client_CA(ctx: PSSL_CTX; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_add_client_CA');
end;

procedure ERROR_SSL_set_connect_state(s: PSSL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_connect_state');
end;

procedure ERROR_SSL_set_accept_state(s: PSSL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_accept_state');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_SSL_library_init: TOpenSSL_C_INT; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_library_init');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_CIPHER_description(cipher: PSSL_CIPHER; buf: PAnsiChar; size_ :TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_description');
end;

function ERROR_SSL_dup(ssl: PSSL): PSSL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dup');
end;

function ERROR_SSL_get_certificate(const ssl: PSSL): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_certificate');
end;

function ERROR_SSL_get_privatekey(const ssl: PSSL): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_privatekey');
end;

function ERROR_SSL_CTX_get0_certificate(const ctx: PSSL_CTX): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_certificate');
end;

function ERROR_SSL_CTX_get0_privatekey(const ctx: PSSL_CTX): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_privatekey');
end;

procedure ERROR_SSL_CTX_set_quiet_shutdown(ctx: PSSL_CTX; mode: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_quiet_shutdown');
end;

function ERROR_SSL_CTX_get_quiet_shutdown(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_quiet_shutdown');
end;

procedure ERROR_SSL_set_quiet_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_quiet_shutdown');
end;

function ERROR_SSL_get_quiet_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_quiet_shutdown');
end;

procedure ERROR_SSL_set_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_shutdown');
end;

function ERROR_SSL_get_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_shutdown');
end;

function ERROR_SSL_version(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_version');
end;

function ERROR_SSL_client_version(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_version');
end;

function ERROR_SSL_CTX_set_default_verify_paths(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_verify_paths');
end;

function ERROR_SSL_CTX_set_default_verify_dir(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_verify_dir');
end;

function ERROR_SSL_CTX_set_default_verify_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_verify_file');
end;

function ERROR_SSL_CTX_load_verify_locations(ctx: PSSL_CTX; const CAfile: PAnsiChar; const CApath: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_load_verify_locations');
end;

function ERROR_SSL_get_session(const ssl: PSSL): PSSL_SESSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_session');
end;

function ERROR_SSL_get1_session(ssl: PSSL): PSSL_SESSION; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get1_session');
end;

function ERROR_SSL_get_SSL_CTX(const ssl: PSSL): PSSL_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_SSL_CTX');
end;

function ERROR_SSL_set_SSL_CTX(ssl: PSSL; ctx: PSSL_CTX): PSSL_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_SSL_CTX');
end;

procedure ERROR_SSL_set_info_callback(ssl: PSSL; cb: SSL_info_callback); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_info_callback');
end;

function ERROR_SSL_get_info_callback(const ssl: PSSL): SSL_info_callback; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_info_callback');
end;

function ERROR_SSL_get_state(const ssl: PSSL): OSSL_HANDSHAKE_STATE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_state');
end;

procedure ERROR_SSL_set_verify_result(ssl: PSSL; v: TOpenSSL_C_LONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_verify_result');
end;

function ERROR_SSL_get_verify_result(const ssl: PSSL): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_result');
end;

function ERROR_SSL_get_client_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_client_random');
end;

function ERROR_SSL_get_server_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_server_random');
end;

function ERROR_SSL_SESSION_get_master_key(const sess: PSSL_SESSION; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_master_key');
end;

function ERROR_SSL_SESSION_set1_master_key(sess: PSSL_SESSION; const in_: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_master_key');
end;

function ERROR_SSL_SESSION_get_max_fragment_length(const sess: PSSL_SESSION): TOpenSSL_C_UINT8; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_max_fragment_length');
end;

function ERROR_SSL_set_ex_data(ssl: PSSL; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_ex_data');
end;

function ERROR_SSL_get_ex_data(const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_ex_data');
end;

function ERROR_SSL_SESSION_set_ex_data(ss: PSSL_SESSION; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_ex_data');
end;

function ERROR_SSL_SESSION_get_ex_data(const ss: PSSL_SESSION; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_ex_data');
end;

function ERROR_SSL_CTX_set_ex_data(ssl: PSSL_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ex_data');
end;

function ERROR_SSL_CTX_get_ex_data(const ssl: PSSL_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_ex_data');
end;

function ERROR_SSL_get_ex_data_X509_STORE_CTX_idx: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_ex_data_X509_STORE_CTX_idx');
end;

procedure ERROR_SSL_CTX_set_default_read_buffer_len(ctx: PSSL_CTX; len: TOpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_read_buffer_len');
end;

procedure ERROR_SSL_set_default_read_buffer_len(s: PSSL; len: TOpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_default_read_buffer_len');
end;

procedure ERROR_SSL_CTX_set_tmp_dh_callback(ctx: PSSL_CTX; dh: SSL_CTX_set_tmp_dh_callback_dh); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_tmp_dh_callback');
end;

procedure ERROR_SSL_set_tmp_dh_callback(ssl: PSSL; dh: SSL_set_tmp_dh_callback_dh); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_tmp_dh_callback');
end;

function ERROR_SSL_CIPHER_find(ssl: PSSL; const ptr: PByte): PSSL_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_find');
end;

function ERROR_SSL_CIPHER_get_cipher_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_cipher_nid');
end;

function ERROR_SSL_CIPHER_get_digest_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_digest_nid');
end;

function ERROR_SSL_set_session_ticket_ext(s: PSSL; ext_data: Pointer; ext_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session_ticket_ext');
end;

function ERROR_SSL_set_session_ticket_ext_cb(s: PSSL; cb: tls_session_ticket_ext_cb_fn; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session_ticket_ext_cb');
end;

procedure ERROR_SSL_CTX_set_not_resumable_session_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_not_resumable_session_callback_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_not_resumable_session_callback');
end;

procedure ERROR_SSL_set_not_resumable_session_callback(ssl: PSSL; cb: SSL_set_not_resumable_session_callback_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_not_resumable_session_callback');
end;

procedure ERROR_SSL_CTX_set_record_padding_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_record_padding_callback_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_record_padding_callback');
end;

procedure ERROR_SSL_CTX_set_record_padding_callback_arg(ctx: PSSL_CTX; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_record_padding_callback_arg');
end;

function ERROR_SSL_CTX_get_record_padding_callback_arg(const ctx: PSSL_CTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_record_padding_callback_arg');
end;

function ERROR_SSL_CTX_set_block_padding(ctx: PSSL_CTX; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_block_padding');
end;

procedure ERROR_SSL_set_record_padding_callback(ssl: PSSL; cb: SSL_set_record_padding_callback_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_record_padding_callback');
end;

procedure ERROR_SSL_set_record_padding_callback_arg(ssl: PSSL; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_record_padding_callback_arg');
end;

function ERROR_SSL_get_record_padding_callback_arg(const ssl: PSSL): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_record_padding_callback_arg');
end;

function ERROR_SSL_set_block_padding(ssl: PSSL; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_block_padding');
end;

function ERROR_SSL_set_num_tickets(s: PSSL; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_num_tickets');
end;

function ERROR_SSL_get_num_tickets(const s: PSSL): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_num_tickets');
end;

function ERROR_SSL_CTX_set_num_tickets(ctx: PSSL_CTX; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_num_tickets');
end;

function ERROR_SSL_CTX_get_num_tickets(const ctx: PSSL_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_num_tickets');
end;

function ERROR_SSL_session_reused(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_session_reused');
end;

function ERROR_SSL_is_server(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_is_server');
end;

function ERROR_SSL_CONF_CTX_new: PSSL_CONF_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_new');
end;

function ERROR_SSL_CONF_CTX_finish(cctx: PSSL_CONF_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_finish');
end;

procedure ERROR_SSL_CONF_CTX_free(cctx: PSSL_CONF_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_free');
end;

function ERROR_SSL_CONF_CTX_set_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set_flags');
end;

function ERROR_SSL_CONF_CTX_clear_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_clear_flags');
end;

function ERROR_SSL_CONF_CTX_set1_prefix(cctx: PSSL_CONF_CTX; const pre: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set1_prefix');
end;

function ERROR_SSL_CONF_cmd(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_cmd');
end;

function ERROR_SSL_CONF_cmd_argv(cctx: PSSL_CONF_CTX; pargc: POpenSSL_C_INT; pargv: PPPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_cmd_argv');
end;

function ERROR_SSL_CONF_cmd_value_type(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_cmd_value_type');
end;

procedure ERROR_SSL_CONF_CTX_set_ssl(cctx: PSSL_CONF_CTX; ssl: PSSL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set_ssl');
end;

procedure ERROR_SSL_CONF_CTX_set_ssl_ctx(cctx: PSSL_CONF_CTX; ctx: PSSL_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set_ssl_ctx');
end;

procedure ERROR_SSL_add_ssl_module; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_ssl_module');
end;

function ERROR_SSL_config(s: PSSL; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_config');
end;

function ERROR_SSL_CTX_config(ctx: PSSL_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_config');
end;

function ERROR_DTLSv1_listen(s: PSSL; client: PBIO_ADDr): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DTLSv1_listen');
end;

function ERROR_SSL_enable_ct(s: PSSL; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_enable_ct');
end;

function ERROR_SSL_CTX_enable_ct(ctx: PSSL_CTX; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_enable_ct');
end;

function ERROR_SSL_ct_is_enabled(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ct_is_enabled');
end;

function ERROR_SSL_CTX_ct_is_enabled(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_ct_is_enabled');
end;

function ERROR_SSL_CTX_set_default_ctlog_list_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_ctlog_list_file');
end;

function ERROR_SSL_CTX_set_ctlog_list_file(ctx: PSSL_CTX; const path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ctlog_list_file');
end;

procedure ERROR_SSL_CTX_set0_ctlog_store(ctx: PSSL_CTX; logs: PCTLOG_STORE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set0_ctlog_store');
end;

procedure ERROR_SSL_set_security_level(s: PSSL; level: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_security_level');
end;

procedure ERROR_SSL_set_security_callback(s: PSSL; cb: SSL_security_callback); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_security_callback');
end;

function ERROR_SSL_get_security_callback(const s: PSSL): SSL_security_callback; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_security_callback');
end;

procedure ERROR_SSL_set0_security_ex_data(s: PSSL; ex: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_security_ex_data');
end;

function ERROR_SSL_get0_security_ex_data(const s: PSSL): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_security_ex_data');
end;

procedure ERROR_SSL_CTX_set_security_level(ctx: PSSL_CTX; level: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_security_level');
end;

function ERROR_SSL_CTX_get_security_level(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_security_level');
end;

function ERROR_SSL_CTX_get0_security_ex_data(const ctx: PSSL_CTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_security_ex_data');
end;

procedure ERROR_SSL_CTX_set0_security_ex_data(ctx: PSSL_CTX; ex: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set0_security_ex_data');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_init_ssl');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_SSL_free_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_free_buffers');
end;

function ERROR_SSL_alloc_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alloc_buffers');
end;

function ERROR_SSL_CTX_set_session_ticket_cb(ctx: PSSL_CTX; gen_cb: SSL_CTX_generate_session_ticket_fn; dec_cb: SSL_CTX_decrypt_session_ticket_fn; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_session_ticket_cb');
end;

function ERROR_SSL_SESSION_set1_ticket_appdata(ss: PSSL_SESSION; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_ticket_appdata');
end;

function ERROR_SSL_SESSION_get0_ticket_appdata(ss: PSSL_SESSION; data: PPointer; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_ticket_appdata');
end;

procedure ERROR_DTLS_set_timer_cb(s: PSSL; cb: DTLS_timer_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DTLS_set_timer_cb');
end;

procedure ERROR_SSL_CTX_set_allow_early_data_cb(ctx: PSSL_CTX; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_allow_early_data_cb');
end;

procedure ERROR_SSL_set_allow_early_data_cb(s: PSSL; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_allow_early_data_cb');
end;

function ERROR_SSL_get0_peer_certificate(const s: PSSL): PX509; cdecl; {introduced 3.3.0 }
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_peer_certificate');
end;

function ERROR_SSL_get1_peer_certificate(const s: PSSL): PX509; cdecl; {introduced 3.3.0 }
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get1_peer_certificate');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_CTX_set_mode := LoadLibSSLFunction('SSL_CTX_set_mode');
  FuncLoadError := not assigned(SSL_CTX_set_mode);
  if FuncLoadError then
  begin
    SSL_CTX_set_mode := @COMPAT_SSL_CTX_set_mode;
    if SSL_CTX_set_mode_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set_mode');
  end;

  SSL_CTX_clear_mode := LoadLibSSLFunction('SSL_CTX_clear_mode');
  FuncLoadError := not assigned(SSL_CTX_clear_mode);
  if FuncLoadError then
  begin
    SSL_CTX_clear_mode := @COMPAT_SSL_CTX_clear_mode;
    if SSL_CTX_clear_mode_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_clear_mode');
  end;

  SSL_CTX_sess_set_cache_size := LoadLibSSLFunction('SSL_CTX_sess_set_cache_size');
  FuncLoadError := not assigned(SSL_CTX_sess_set_cache_size);
  if FuncLoadError then
  begin
    SSL_CTX_sess_set_cache_size := @COMPAT_SSL_CTX_sess_set_cache_size;
    if SSL_CTX_sess_set_cache_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_sess_set_cache_size');
  end;

  SSL_CTX_sess_get_cache_size := LoadLibSSLFunction('SSL_CTX_sess_get_cache_size');
  FuncLoadError := not assigned(SSL_CTX_sess_get_cache_size);
  if FuncLoadError then
  begin
    SSL_CTX_sess_get_cache_size := @COMPAT_SSL_CTX_sess_get_cache_size;
    if SSL_CTX_sess_get_cache_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_sess_get_cache_size');
  end;

  SSL_CTX_set_session_cache_mode := LoadLibSSLFunction('SSL_CTX_set_session_cache_mode');
  FuncLoadError := not assigned(SSL_CTX_set_session_cache_mode);
  if FuncLoadError then
  begin
    SSL_CTX_set_session_cache_mode := @COMPAT_SSL_CTX_set_session_cache_mode;
    if SSL_CTX_set_session_cache_mode_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set_session_cache_mode');
  end;

  SSL_CTX_get_session_cache_mode := LoadLibSSLFunction('SSL_CTX_get_session_cache_mode');
  FuncLoadError := not assigned(SSL_CTX_get_session_cache_mode);
  if FuncLoadError then
  begin
    SSL_CTX_get_session_cache_mode := @COMPAT_SSL_CTX_get_session_cache_mode;
    if SSL_CTX_get_session_cache_mode_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_get_session_cache_mode');
  end;

  SSL_clear_num_renegotiations := LoadLibSSLFunction('SSL_clear_num_renegotiations');
  FuncLoadError := not assigned(SSL_clear_num_renegotiations);
  if FuncLoadError then
  begin
    SSL_clear_num_renegotiations := @COMPAT_SSL_clear_num_renegotiations;
    if SSL_clear_num_renegotiations_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_clear_num_renegotiations');
  end;

  SSL_total_renegotiations := LoadLibSSLFunction('SSL_total_renegotiations');
  FuncLoadError := not assigned(SSL_total_renegotiations);
  if FuncLoadError then
  begin
    SSL_total_renegotiations := @COMPAT_SSL_total_renegotiations;
    if SSL_total_renegotiations_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_total_renegotiations');
  end;

  SSL_CTX_set_tmp_dh := LoadLibSSLFunction('SSL_CTX_set_tmp_dh');
  FuncLoadError := not assigned(SSL_CTX_set_tmp_dh);
  if FuncLoadError then
  begin
    SSL_CTX_set_tmp_dh := @COMPAT_SSL_CTX_set_tmp_dh;
    if SSL_CTX_set_tmp_dh_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set_tmp_dh');
  end;

  SSL_CTX_set_tmp_ecdh := LoadLibSSLFunction('SSL_CTX_set_tmp_ecdh');
  FuncLoadError := not assigned(SSL_CTX_set_tmp_ecdh);
  if FuncLoadError then
  begin
    SSL_CTX_set_tmp_ecdh := @COMPAT_SSL_CTX_set_tmp_ecdh;
    if SSL_CTX_set_tmp_ecdh_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set_tmp_ecdh');
  end;

  SSL_CTX_set_dh_auto := LoadLibSSLFunction('SSL_CTX_set_dh_auto');
  FuncLoadError := not assigned(SSL_CTX_set_dh_auto);
  if FuncLoadError then
  begin
    SSL_CTX_set_dh_auto := @COMPAT_SSL_CTX_set_dh_auto;
    if SSL_CTX_set_dh_auto_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set_dh_auto');
  end;

  SSL_set_dh_auto := LoadLibSSLFunction('SSL_set_dh_auto');
  FuncLoadError := not assigned(SSL_set_dh_auto);
  if FuncLoadError then
  begin
    SSL_set_dh_auto := @COMPAT_SSL_set_dh_auto;
    if SSL_set_dh_auto_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set_dh_auto');
  end;

  SSL_set_tmp_dh := LoadLibSSLFunction('SSL_set_tmp_dh');
  FuncLoadError := not assigned(SSL_set_tmp_dh);
  if FuncLoadError then
  begin
    SSL_set_tmp_dh := @COMPAT_SSL_set_tmp_dh;
    if SSL_set_tmp_dh_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set_tmp_dh');
  end;

  SSL_set_tmp_ecdh := LoadLibSSLFunction('SSL_set_tmp_ecdh');
  FuncLoadError := not assigned(SSL_set_tmp_ecdh);
  if FuncLoadError then
  begin
    SSL_set_tmp_ecdh := @COMPAT_SSL_set_tmp_ecdh;
    if SSL_set_tmp_ecdh_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set_tmp_ecdh');
  end;

  SSL_CTX_add_extra_chain_cert := LoadLibSSLFunction('SSL_CTX_add_extra_chain_cert');
  FuncLoadError := not assigned(SSL_CTX_add_extra_chain_cert);
  if FuncLoadError then
  begin
    SSL_CTX_add_extra_chain_cert := @COMPAT_SSL_CTX_add_extra_chain_cert;
    if SSL_CTX_add_extra_chain_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_add_extra_chain_cert');
  end;

  SSL_CTX_get_extra_chain_certs := LoadLibSSLFunction('SSL_CTX_get_extra_chain_certs');
  FuncLoadError := not assigned(SSL_CTX_get_extra_chain_certs);
  if FuncLoadError then
  begin
    SSL_CTX_get_extra_chain_certs := @COMPAT_SSL_CTX_get_extra_chain_certs;
    if SSL_CTX_get_extra_chain_certs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_get_extra_chain_certs');
  end;

  SSL_CTX_get_extra_chain_certs_only := LoadLibSSLFunction('SSL_CTX_get_extra_chain_certs_only');
  FuncLoadError := not assigned(SSL_CTX_get_extra_chain_certs_only);
  if FuncLoadError then
  begin
    SSL_CTX_get_extra_chain_certs_only := @COMPAT_SSL_CTX_get_extra_chain_certs_only;
    if SSL_CTX_get_extra_chain_certs_only_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_get_extra_chain_certs_only');
  end;

  SSL_CTX_clear_extra_chain_certs := LoadLibSSLFunction('SSL_CTX_clear_extra_chain_certs');
  FuncLoadError := not assigned(SSL_CTX_clear_extra_chain_certs);
  if FuncLoadError then
  begin
    SSL_CTX_clear_extra_chain_certs := @COMPAT_SSL_CTX_clear_extra_chain_certs;
    if SSL_CTX_clear_extra_chain_certs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_clear_extra_chain_certs');
  end;

  SSL_CTX_set0_chain := LoadLibSSLFunction('SSL_CTX_set0_chain');
  FuncLoadError := not assigned(SSL_CTX_set0_chain);
  if FuncLoadError then
  begin
    SSL_CTX_set0_chain := @COMPAT_SSL_CTX_set0_chain;
    if SSL_CTX_set0_chain_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set0_chain');
  end;

  SSL_CTX_set1_chain := LoadLibSSLFunction('SSL_CTX_set1_chain');
  FuncLoadError := not assigned(SSL_CTX_set1_chain);
  if FuncLoadError then
  begin
    SSL_CTX_set1_chain := @COMPAT_SSL_CTX_set1_chain;
    if SSL_CTX_set1_chain_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_chain');
  end;

  SSL_CTX_add0_chain_cert := LoadLibSSLFunction('SSL_CTX_add0_chain_cert');
  FuncLoadError := not assigned(SSL_CTX_add0_chain_cert);
  if FuncLoadError then
  begin
    SSL_CTX_add0_chain_cert := @COMPAT_SSL_CTX_add0_chain_cert;
    if SSL_CTX_add0_chain_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_add0_chain_cert');
  end;

  SSL_CTX_add1_chain_cert := LoadLibSSLFunction('SSL_CTX_add1_chain_cert');
  FuncLoadError := not assigned(SSL_CTX_add1_chain_cert);
  if FuncLoadError then
  begin
    SSL_CTX_add1_chain_cert := @COMPAT_SSL_CTX_add1_chain_cert;
    if SSL_CTX_add1_chain_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_add1_chain_cert');
  end;

  SSL_CTX_get0_chain_certs := LoadLibSSLFunction('SSL_CTX_get0_chain_certs');
  FuncLoadError := not assigned(SSL_CTX_get0_chain_certs);
  if FuncLoadError then
  begin
    SSL_CTX_get0_chain_certs := @COMPAT_SSL_CTX_get0_chain_certs;
    if SSL_CTX_get0_chain_certs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_get0_chain_certs');
  end;

  SSL_CTX_clear_chain_certs := LoadLibSSLFunction('SSL_CTX_clear_chain_certs');
  FuncLoadError := not assigned(SSL_CTX_clear_chain_certs);
  if FuncLoadError then
  begin
    SSL_CTX_clear_chain_certs := @COMPAT_SSL_CTX_clear_chain_certs;
    if SSL_CTX_clear_chain_certs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_clear_chain_certs');
  end;

  SSL_CTX_build_cert_chain := LoadLibSSLFunction('SSL_CTX_build_cert_chain');
  FuncLoadError := not assigned(SSL_CTX_build_cert_chain);
  if FuncLoadError then
  begin
    SSL_CTX_build_cert_chain := @COMPAT_SSL_CTX_build_cert_chain;
    if SSL_CTX_build_cert_chain_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_build_cert_chain');
  end;

  SSL_CTX_select_current_cert := LoadLibSSLFunction('SSL_CTX_select_current_cert');
  FuncLoadError := not assigned(SSL_CTX_select_current_cert);
  if FuncLoadError then
  begin
    SSL_CTX_select_current_cert := @COMPAT_SSL_CTX_select_current_cert;
    if SSL_CTX_select_current_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_select_current_cert');
  end;

  SSL_CTX_set_current_cert := LoadLibSSLFunction('SSL_CTX_set_current_cert');
  FuncLoadError := not assigned(SSL_CTX_set_current_cert);
  if FuncLoadError then
  begin
    SSL_CTX_set_current_cert := @COMPAT_SSL_CTX_set_current_cert;
    if SSL_CTX_set_current_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set_current_cert');
  end;

  SSL_CTX_set0_verify_cert_store := LoadLibSSLFunction('SSL_CTX_set0_verify_cert_store');
  FuncLoadError := not assigned(SSL_CTX_set0_verify_cert_store);
  if FuncLoadError then
  begin
    SSL_CTX_set0_verify_cert_store := @COMPAT_SSL_CTX_set0_verify_cert_store;
    if SSL_CTX_set0_verify_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set0_verify_cert_store');
  end;

  SSL_CTX_set1_verify_cert_store := LoadLibSSLFunction('SSL_CTX_set1_verify_cert_store');
  FuncLoadError := not assigned(SSL_CTX_set1_verify_cert_store);
  if FuncLoadError then
  begin
    SSL_CTX_set1_verify_cert_store := @COMPAT_SSL_CTX_set1_verify_cert_store;
    if SSL_CTX_set1_verify_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_verify_cert_store');
  end;

  SSL_CTX_set0_chain_cert_store := LoadLibSSLFunction('SSL_CTX_set0_chain_cert_store');
  FuncLoadError := not assigned(SSL_CTX_set0_chain_cert_store);
  if FuncLoadError then
  begin
    SSL_CTX_set0_chain_cert_store := @COMPAT_SSL_CTX_set0_chain_cert_store;
    if SSL_CTX_set0_chain_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set0_chain_cert_store');
  end;

  SSL_CTX_set1_chain_cert_store := LoadLibSSLFunction('SSL_CTX_set1_chain_cert_store');
  FuncLoadError := not assigned(SSL_CTX_set1_chain_cert_store);
  if FuncLoadError then
  begin
    SSL_CTX_set1_chain_cert_store := @COMPAT_SSL_CTX_set1_chain_cert_store;
    if SSL_CTX_set1_chain_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_chain_cert_store');
  end;

  SSL_set0_chain := LoadLibSSLFunction('SSL_set0_chain');
  FuncLoadError := not assigned(SSL_set0_chain);
  if FuncLoadError then
  begin
    SSL_set0_chain := @COMPAT_SSL_set0_chain;
    if SSL_set0_chain_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set0_chain');
  end;

  SSL_set1_chain := LoadLibSSLFunction('SSL_set1_chain');
  FuncLoadError := not assigned(SSL_set1_chain);
  if FuncLoadError then
  begin
    SSL_set1_chain := @COMPAT_SSL_set1_chain;
    if SSL_set1_chain_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_chain');
  end;

  SSL_add0_chain_cert := LoadLibSSLFunction('SSL_add0_chain_cert');
  FuncLoadError := not assigned(SSL_add0_chain_cert);
  if FuncLoadError then
  begin
    SSL_add0_chain_cert := @COMPAT_SSL_add0_chain_cert;
    if SSL_add0_chain_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_add0_chain_cert');
  end;

  SSL_add1_chain_cert := LoadLibSSLFunction('SSL_add1_chain_cert');
  FuncLoadError := not assigned(SSL_add1_chain_cert);
  if FuncLoadError then
  begin
    SSL_add1_chain_cert := @COMPAT_SSL_add1_chain_cert;
    if SSL_add1_chain_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_add1_chain_cert');
  end;

  SSL_get0_chain_certs := LoadLibSSLFunction('SSL_get0_chain_certs');
  FuncLoadError := not assigned(SSL_get0_chain_certs);
  if FuncLoadError then
  begin
    SSL_get0_chain_certs := @COMPAT_SSL_get0_chain_certs;
    if SSL_get0_chain_certs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get0_chain_certs');
  end;

  SSL_clear_chain_certs := LoadLibSSLFunction('SSL_clear_chain_certs');
  FuncLoadError := not assigned(SSL_clear_chain_certs);
  if FuncLoadError then
  begin
    SSL_clear_chain_certs := @COMPAT_SSL_clear_chain_certs;
    if SSL_clear_chain_certs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_clear_chain_certs');
  end;

  SSL_build_cert_chain := LoadLibSSLFunction('SSL_build_cert_chain');
  FuncLoadError := not assigned(SSL_build_cert_chain);
  if FuncLoadError then
  begin
    SSL_build_cert_chain := @COMPAT_SSL_build_cert_chain;
    if SSL_build_cert_chain_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_build_cert_chain');
  end;

  SSL_select_current_cert := LoadLibSSLFunction('SSL_select_current_cert');
  FuncLoadError := not assigned(SSL_select_current_cert);
  if FuncLoadError then
  begin
    SSL_select_current_cert := @COMPAT_SSL_select_current_cert;
    if SSL_select_current_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_select_current_cert');
  end;

  SSL_set_current_cert := LoadLibSSLFunction('SSL_set_current_cert');
  FuncLoadError := not assigned(SSL_set_current_cert);
  if FuncLoadError then
  begin
    SSL_set_current_cert := @COMPAT_SSL_set_current_cert;
    if SSL_set_current_cert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set_current_cert');
  end;

  SSL_set0_verify_cert_store := LoadLibSSLFunction('SSL_set0_verify_cert_store');
  FuncLoadError := not assigned(SSL_set0_verify_cert_store);
  if FuncLoadError then
  begin
    SSL_set0_verify_cert_store := @COMPAT_SSL_set0_verify_cert_store;
    if SSL_set0_verify_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set0_verify_cert_store');
  end;

  SSL_set1_verify_cert_store := LoadLibSSLFunction('SSL_set1_verify_cert_store');
  FuncLoadError := not assigned(SSL_set1_verify_cert_store);
  if FuncLoadError then
  begin
    SSL_set1_verify_cert_store := @COMPAT_SSL_set1_verify_cert_store;
    if SSL_set1_verify_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_verify_cert_store');
  end;

  SSL_set0_chain_cert_store := LoadLibSSLFunction('SSL_set0_chain_cert_store');
  FuncLoadError := not assigned(SSL_set0_chain_cert_store);
  if FuncLoadError then
  begin
    SSL_set0_chain_cert_store := @COMPAT_SSL_set0_chain_cert_store;
    if SSL_set0_chain_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set0_chain_cert_store');
  end;

  SSL_set1_chain_cert_store := LoadLibSSLFunction('SSL_set1_chain_cert_store');
  FuncLoadError := not assigned(SSL_set1_chain_cert_store);
  if FuncLoadError then
  begin
    SSL_set1_chain_cert_store := @COMPAT_SSL_set1_chain_cert_store;
    if SSL_set1_chain_cert_store_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_chain_cert_store');
  end;

  SSL_get1_groups := LoadLibSSLFunction('SSL_get1_groups');
  FuncLoadError := not assigned(SSL_get1_groups);
  if FuncLoadError then
  begin
    SSL_get1_groups := @COMPAT_SSL_get1_groups;
    if SSL_get1_groups_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get1_groups');
  end;

  SSL_CTX_set1_groups := LoadLibSSLFunction('SSL_CTX_set1_groups');
  FuncLoadError := not assigned(SSL_CTX_set1_groups);
  if FuncLoadError then
  begin
    SSL_CTX_set1_groups := @COMPAT_SSL_CTX_set1_groups;
    if SSL_CTX_set1_groups_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_groups');
  end;

  SSL_CTX_set1_groups_list := LoadLibSSLFunction('SSL_CTX_set1_groups_list');
  FuncLoadError := not assigned(SSL_CTX_set1_groups_list);
  if FuncLoadError then
  begin
    SSL_CTX_set1_groups_list := @COMPAT_SSL_CTX_set1_groups_list;
    if SSL_CTX_set1_groups_list_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_groups_list');
  end;

  SSL_set1_groups := LoadLibSSLFunction('SSL_set1_groups');
  FuncLoadError := not assigned(SSL_set1_groups);
  if FuncLoadError then
  begin
    SSL_set1_groups := @COMPAT_SSL_set1_groups;
    if SSL_set1_groups_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_groups');
  end;

  SSL_set1_groups_list := LoadLibSSLFunction('SSL_set1_groups_list');
  FuncLoadError := not assigned(SSL_set1_groups_list);
  if FuncLoadError then
  begin
    SSL_set1_groups_list := @COMPAT_SSL_set1_groups_list;
    if SSL_set1_groups_list_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_groups_list');
  end;

  SSL_get_shared_group := LoadLibSSLFunction('SSL_get_shared_group');
  FuncLoadError := not assigned(SSL_get_shared_group);
  if FuncLoadError then
  begin
    SSL_get_shared_group := @COMPAT_SSL_get_shared_group;
    if SSL_get_shared_group_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get_shared_group');
  end;

  SSL_CTX_set1_sigalgs := LoadLibSSLFunction('SSL_CTX_set1_sigalgs');
  FuncLoadError := not assigned(SSL_CTX_set1_sigalgs);
  if FuncLoadError then
  begin
    SSL_CTX_set1_sigalgs := @COMPAT_SSL_CTX_set1_sigalgs;
    if SSL_CTX_set1_sigalgs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_sigalgs');
  end;

  SSL_CTX_set1_sigalgs_list := LoadLibSSLFunction('SSL_CTX_set1_sigalgs_list');
  FuncLoadError := not assigned(SSL_CTX_set1_sigalgs_list);
  if FuncLoadError then
  begin
    SSL_CTX_set1_sigalgs_list := @COMPAT_SSL_CTX_set1_sigalgs_list;
    if SSL_CTX_set1_sigalgs_list_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_sigalgs_list');
  end;

  SSL_set1_sigalgs := LoadLibSSLFunction('SSL_set1_sigalgs');
  FuncLoadError := not assigned(SSL_set1_sigalgs);
  if FuncLoadError then
  begin
    SSL_set1_sigalgs := @COMPAT_SSL_set1_sigalgs;
    if SSL_set1_sigalgs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_sigalgs');
  end;

  SSL_set1_sigalgs_list := LoadLibSSLFunction('SSL_set1_sigalgs_list');
  FuncLoadError := not assigned(SSL_set1_sigalgs_list);
  if FuncLoadError then
  begin
    SSL_set1_sigalgs_list := @COMPAT_SSL_set1_sigalgs_list;
    if SSL_set1_sigalgs_list_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_sigalgs_list');
  end;

  SSL_CTX_set1_client_sigalgs := LoadLibSSLFunction('SSL_CTX_set1_client_sigalgs');
  FuncLoadError := not assigned(SSL_CTX_set1_client_sigalgs);
  if FuncLoadError then
  begin
    SSL_CTX_set1_client_sigalgs := @COMPAT_SSL_CTX_set1_client_sigalgs;
    if SSL_CTX_set1_client_sigalgs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_client_sigalgs');
  end;

  SSL_CTX_set1_client_sigalgs_list := LoadLibSSLFunction('SSL_CTX_set1_client_sigalgs_list');
  FuncLoadError := not assigned(SSL_CTX_set1_client_sigalgs_list);
  if FuncLoadError then
  begin
    SSL_CTX_set1_client_sigalgs_list := @COMPAT_SSL_CTX_set1_client_sigalgs_list;
    if SSL_CTX_set1_client_sigalgs_list_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_client_sigalgs_list');
  end;

  SSL_set1_client_sigalgs := LoadLibSSLFunction('SSL_set1_client_sigalgs');
  FuncLoadError := not assigned(SSL_set1_client_sigalgs);
  if FuncLoadError then
  begin
    SSL_set1_client_sigalgs := @COMPAT_SSL_set1_client_sigalgs;
    if SSL_set1_client_sigalgs_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_client_sigalgs');
  end;

  SSL_set1_client_sigalgs_list := LoadLibSSLFunction('SSL_set1_client_sigalgs_list');
  FuncLoadError := not assigned(SSL_set1_client_sigalgs_list);
  if FuncLoadError then
  begin
    SSL_set1_client_sigalgs_list := @COMPAT_SSL_set1_client_sigalgs_list;
    if SSL_set1_client_sigalgs_list_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_client_sigalgs_list');
  end;

  SSL_get0_certificate_types := LoadLibSSLFunction('SSL_get0_certificate_types');
  FuncLoadError := not assigned(SSL_get0_certificate_types);
  if FuncLoadError then
  begin
    SSL_get0_certificate_types := @COMPAT_SSL_get0_certificate_types;
    if SSL_get0_certificate_types_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get0_certificate_types');
  end;

  SSL_CTX_set1_client_certificate_types := LoadLibSSLFunction('SSL_CTX_set1_client_certificate_types');
  FuncLoadError := not assigned(SSL_CTX_set1_client_certificate_types);
  if FuncLoadError then
  begin
    SSL_CTX_set1_client_certificate_types := @COMPAT_SSL_CTX_set1_client_certificate_types;
    if SSL_CTX_set1_client_certificate_types_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_client_certificate_types');
  end;

  SSL_set1_client_certificate_types := LoadLibSSLFunction('SSL_set1_client_certificate_types');
  FuncLoadError := not assigned(SSL_set1_client_certificate_types);
  if FuncLoadError then
  begin
    SSL_set1_client_certificate_types := @COMPAT_SSL_set1_client_certificate_types;
    if SSL_set1_client_certificate_types_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set1_client_certificate_types');
  end;

  SSL_get_signature_nid := LoadLibSSLFunction('SSL_get_signature_nid');
  FuncLoadError := not assigned(SSL_get_signature_nid);
  if FuncLoadError then
  begin
    SSL_get_signature_nid := @COMPAT_SSL_get_signature_nid;
    if SSL_get_signature_nid_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get_signature_nid');
  end;

  SSL_get_peer_signature_nid := LoadLibSSLFunction('SSL_get_peer_signature_nid');
  FuncLoadError := not assigned(SSL_get_peer_signature_nid);
  if FuncLoadError then
  begin
    SSL_get_peer_signature_nid := @COMPAT_SSL_get_peer_signature_nid;
    if SSL_get_peer_signature_nid_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get_peer_signature_nid');
  end;

  SSL_get_peer_tmp_key := LoadLibSSLFunction('SSL_get_peer_tmp_key');
  FuncLoadError := not assigned(SSL_get_peer_tmp_key);
  if FuncLoadError then
  begin
    SSL_get_peer_tmp_key := @COMPAT_SSL_get_peer_tmp_key;
    if SSL_get_peer_tmp_key_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get_peer_tmp_key');
  end;

  SSL_get_tmp_key := LoadLibSSLFunction('SSL_get_tmp_key');
  FuncLoadError := not assigned(SSL_get_tmp_key);
  if FuncLoadError then
  begin
    SSL_get_tmp_key := @COMPAT_SSL_get_tmp_key;
    if SSL_get_tmp_key_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get_tmp_key');
  end;

  SSL_get0_raw_cipherlist := LoadLibSSLFunction('SSL_get0_raw_cipherlist');
  FuncLoadError := not assigned(SSL_get0_raw_cipherlist);
  if FuncLoadError then
  begin
    SSL_get0_raw_cipherlist := @COMPAT_SSL_get0_raw_cipherlist;
    if SSL_get0_raw_cipherlist_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get0_raw_cipherlist');
  end;

  SSL_get0_ec_point_formats := LoadLibSSLFunction('SSL_get0_ec_point_formats');
  FuncLoadError := not assigned(SSL_get0_ec_point_formats);
  if FuncLoadError then
  begin
    SSL_get0_ec_point_formats := @COMPAT_SSL_get0_ec_point_formats;
    if SSL_get0_ec_point_formats_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get0_ec_point_formats');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CTX_get_options := LoadLibSSLFunction('SSL_CTX_get_options');
  FuncLoadError := not assigned(SSL_CTX_get_options);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_options := @COMPAT_SSL_CTX_get_options;
{$ELSE}
    SSL_CTX_get_options :=  @ERROR_SSL_CTX_get_options;
{$ENDIF}
  end;

  SSL_get_options := LoadLibSSLFunction('SSL_get_options');
  FuncLoadError := not assigned(SSL_get_options);
  if FuncLoadError then
  begin
    SSL_get_options :=  @ERROR_SSL_get_options;
  end;

  SSL_CTX_clear_options := LoadLibSSLFunction('SSL_CTX_clear_options');
  FuncLoadError := not assigned(SSL_CTX_clear_options);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_clear_options := @COMPAT_SSL_CTX_clear_options;
{$ELSE}
    SSL_CTX_clear_options :=  @ERROR_SSL_CTX_clear_options;
{$ENDIF}
  end;

  SSL_clear_options := LoadLibSSLFunction('SSL_clear_options');
  FuncLoadError := not assigned(SSL_clear_options);
  if FuncLoadError then
  begin
    SSL_clear_options :=  @ERROR_SSL_clear_options;
  end;

  SSL_CTX_set_options := LoadLibSSLFunction('SSL_CTX_set_options');
  FuncLoadError := not assigned(SSL_CTX_set_options);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_set_options := @COMPAT_SSL_CTX_set_options;
{$ELSE}
    SSL_CTX_set_options :=  @ERROR_SSL_CTX_set_options;
{$ENDIF}
  end;

  SSL_set_options := LoadLibSSLFunction('SSL_set_options');
  FuncLoadError := not assigned(SSL_set_options);
  if FuncLoadError then
  begin
    SSL_set_options :=  @ERROR_SSL_set_options;
  end;

  SSL_CTX_sess_set_new_cb := LoadLibSSLFunction('SSL_CTX_sess_set_new_cb');
  FuncLoadError := not assigned(SSL_CTX_sess_set_new_cb);
  if FuncLoadError then
  begin
    SSL_CTX_sess_set_new_cb :=  @ERROR_SSL_CTX_sess_set_new_cb;
  end;

  SSL_CTX_sess_get_new_cb := LoadLibSSLFunction('SSL_CTX_sess_get_new_cb');
  FuncLoadError := not assigned(SSL_CTX_sess_get_new_cb);
  if FuncLoadError then
  begin
    SSL_CTX_sess_get_new_cb :=  @ERROR_SSL_CTX_sess_get_new_cb;
  end;

  SSL_CTX_sess_set_remove_cb := LoadLibSSLFunction('SSL_CTX_sess_set_remove_cb');
  FuncLoadError := not assigned(SSL_CTX_sess_set_remove_cb);
  if FuncLoadError then
  begin
    SSL_CTX_sess_set_remove_cb :=  @ERROR_SSL_CTX_sess_set_remove_cb;
  end;

  SSL_CTX_sess_get_remove_cb := LoadLibSSLFunction('SSL_CTX_sess_get_remove_cb');
  FuncLoadError := not assigned(SSL_CTX_sess_get_remove_cb);
  if FuncLoadError then
  begin
    SSL_CTX_sess_get_remove_cb :=  @ERROR_SSL_CTX_sess_get_remove_cb;
  end;

  SSL_CTX_set_info_callback := LoadLibSSLFunction('SSL_CTX_set_info_callback');
  FuncLoadError := not assigned(SSL_CTX_set_info_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_info_callback :=  @ERROR_SSL_CTX_set_info_callback;
  end;

  SSL_CTX_get_info_callback := LoadLibSSLFunction('SSL_CTX_get_info_callback');
  FuncLoadError := not assigned(SSL_CTX_get_info_callback);
  if FuncLoadError then
  begin
    SSL_CTX_get_info_callback :=  @ERROR_SSL_CTX_get_info_callback;
  end;

  SSL_CTX_set_client_cert_cb := LoadLibSSLFunction('SSL_CTX_set_client_cert_cb');
  FuncLoadError := not assigned(SSL_CTX_set_client_cert_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_client_cert_cb :=  @ERROR_SSL_CTX_set_client_cert_cb;
  end;

  SSL_CTX_get_client_cert_cb := LoadLibSSLFunction('SSL_CTX_get_client_cert_cb');
  FuncLoadError := not assigned(SSL_CTX_get_client_cert_cb);
  if FuncLoadError then
  begin
    SSL_CTX_get_client_cert_cb :=  @ERROR_SSL_CTX_get_client_cert_cb;
  end;

  SSL_CTX_set_client_cert_engine := LoadLibSSLFunction('SSL_CTX_set_client_cert_engine');
  FuncLoadError := not assigned(SSL_CTX_set_client_cert_engine);
  if FuncLoadError then
  begin
    SSL_CTX_set_client_cert_engine :=  @ERROR_SSL_CTX_set_client_cert_engine;
  end;

  SSL_CTX_set_cookie_generate_cb := LoadLibSSLFunction('SSL_CTX_set_cookie_generate_cb');
  FuncLoadError := not assigned(SSL_CTX_set_cookie_generate_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_cookie_generate_cb :=  @ERROR_SSL_CTX_set_cookie_generate_cb;
  end;

  SSL_CTX_set_cookie_verify_cb := LoadLibSSLFunction('SSL_CTX_set_cookie_verify_cb');
  FuncLoadError := not assigned(SSL_CTX_set_cookie_verify_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_cookie_verify_cb :=  @ERROR_SSL_CTX_set_cookie_verify_cb;
  end;

  SSL_CTX_set_stateless_cookie_generate_cb := LoadLibSSLFunction('SSL_CTX_set_stateless_cookie_generate_cb');
  FuncLoadError := not assigned(SSL_CTX_set_stateless_cookie_generate_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_stateless_cookie_generate_cb :=  @ERROR_SSL_CTX_set_stateless_cookie_generate_cb;
  end;

  SSL_CTX_set_stateless_cookie_verify_cb := LoadLibSSLFunction('SSL_CTX_set_stateless_cookie_verify_cb');
  FuncLoadError := not assigned(SSL_CTX_set_stateless_cookie_verify_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_stateless_cookie_verify_cb :=  @ERROR_SSL_CTX_set_stateless_cookie_verify_cb;
  end;

  SSL_CTX_set_alpn_select_cb := LoadLibSSLFunction('SSL_CTX_set_alpn_select_cb');
  FuncLoadError := not assigned(SSL_CTX_set_alpn_select_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_alpn_select_cb :=  @ERROR_SSL_CTX_set_alpn_select_cb;
  end;

  SSL_get0_alpn_selected := LoadLibSSLFunction('SSL_get0_alpn_selected');
  FuncLoadError := not assigned(SSL_get0_alpn_selected);
  if FuncLoadError then
  begin
    SSL_get0_alpn_selected :=  @ERROR_SSL_get0_alpn_selected;
  end;

  SSL_CTX_set_psk_client_callback := LoadLibSSLFunction('SSL_CTX_set_psk_client_callback');
  FuncLoadError := not assigned(SSL_CTX_set_psk_client_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_psk_client_callback :=  @ERROR_SSL_CTX_set_psk_client_callback;
  end;

  SSL_set_psk_client_callback := LoadLibSSLFunction('SSL_set_psk_client_callback');
  FuncLoadError := not assigned(SSL_set_psk_client_callback);
  if FuncLoadError then
  begin
    SSL_set_psk_client_callback :=  @ERROR_SSL_set_psk_client_callback;
  end;

  SSL_CTX_set_psk_server_callback := LoadLibSSLFunction('SSL_CTX_set_psk_server_callback');
  FuncLoadError := not assigned(SSL_CTX_set_psk_server_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_psk_server_callback :=  @ERROR_SSL_CTX_set_psk_server_callback;
  end;

  SSL_set_psk_server_callback := LoadLibSSLFunction('SSL_set_psk_server_callback');
  FuncLoadError := not assigned(SSL_set_psk_server_callback);
  if FuncLoadError then
  begin
    SSL_set_psk_server_callback :=  @ERROR_SSL_set_psk_server_callback;
  end;

  SSL_set_psk_find_session_callback := LoadLibSSLFunction('SSL_set_psk_find_session_callback');
  FuncLoadError := not assigned(SSL_set_psk_find_session_callback);
  if FuncLoadError then
  begin
    SSL_set_psk_find_session_callback :=  @ERROR_SSL_set_psk_find_session_callback;
  end;

  SSL_CTX_set_psk_find_session_callback := LoadLibSSLFunction('SSL_CTX_set_psk_find_session_callback');
  FuncLoadError := not assigned(SSL_CTX_set_psk_find_session_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_psk_find_session_callback :=  @ERROR_SSL_CTX_set_psk_find_session_callback;
  end;

  SSL_set_psk_use_session_callback := LoadLibSSLFunction('SSL_set_psk_use_session_callback');
  FuncLoadError := not assigned(SSL_set_psk_use_session_callback);
  if FuncLoadError then
  begin
    SSL_set_psk_use_session_callback :=  @ERROR_SSL_set_psk_use_session_callback;
  end;

  SSL_CTX_set_psk_use_session_callback := LoadLibSSLFunction('SSL_CTX_set_psk_use_session_callback');
  FuncLoadError := not assigned(SSL_CTX_set_psk_use_session_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_psk_use_session_callback :=  @ERROR_SSL_CTX_set_psk_use_session_callback;
  end;

  SSL_CTX_set_keylog_callback := LoadLibSSLFunction('SSL_CTX_set_keylog_callback');
  FuncLoadError := not assigned(SSL_CTX_set_keylog_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_keylog_callback :=  @ERROR_SSL_CTX_set_keylog_callback;
  end;

  SSL_CTX_get_keylog_callback := LoadLibSSLFunction('SSL_CTX_get_keylog_callback');
  FuncLoadError := not assigned(SSL_CTX_get_keylog_callback);
  if FuncLoadError then
  begin
    SSL_CTX_get_keylog_callback :=  @ERROR_SSL_CTX_get_keylog_callback;
  end;

  SSL_CTX_set_max_early_data := LoadLibSSLFunction('SSL_CTX_set_max_early_data');
  FuncLoadError := not assigned(SSL_CTX_set_max_early_data);
  if FuncLoadError then
  begin
    SSL_CTX_set_max_early_data :=  @ERROR_SSL_CTX_set_max_early_data;
  end;

  SSL_CTX_get_max_early_data := LoadLibSSLFunction('SSL_CTX_get_max_early_data');
  FuncLoadError := not assigned(SSL_CTX_get_max_early_data);
  if FuncLoadError then
  begin
    SSL_CTX_get_max_early_data :=  @ERROR_SSL_CTX_get_max_early_data;
  end;

  SSL_set_max_early_data := LoadLibSSLFunction('SSL_set_max_early_data');
  FuncLoadError := not assigned(SSL_set_max_early_data);
  if FuncLoadError then
  begin
    SSL_set_max_early_data :=  @ERROR_SSL_set_max_early_data;
  end;

  SSL_get_max_early_data := LoadLibSSLFunction('SSL_get_max_early_data');
  FuncLoadError := not assigned(SSL_get_max_early_data);
  if FuncLoadError then
  begin
    SSL_get_max_early_data :=  @ERROR_SSL_get_max_early_data;
  end;

  SSL_CTX_set_recv_max_early_data := LoadLibSSLFunction('SSL_CTX_set_recv_max_early_data');
  FuncLoadError := not assigned(SSL_CTX_set_recv_max_early_data);
  if FuncLoadError then
  begin
    SSL_CTX_set_recv_max_early_data :=  @ERROR_SSL_CTX_set_recv_max_early_data;
  end;

  SSL_CTX_get_recv_max_early_data := LoadLibSSLFunction('SSL_CTX_get_recv_max_early_data');
  FuncLoadError := not assigned(SSL_CTX_get_recv_max_early_data);
  if FuncLoadError then
  begin
    SSL_CTX_get_recv_max_early_data :=  @ERROR_SSL_CTX_get_recv_max_early_data;
  end;

  SSL_set_recv_max_early_data := LoadLibSSLFunction('SSL_set_recv_max_early_data');
  FuncLoadError := not assigned(SSL_set_recv_max_early_data);
  if FuncLoadError then
  begin
    SSL_set_recv_max_early_data :=  @ERROR_SSL_set_recv_max_early_data;
  end;

  SSL_get_recv_max_early_data := LoadLibSSLFunction('SSL_get_recv_max_early_data');
  FuncLoadError := not assigned(SSL_get_recv_max_early_data);
  if FuncLoadError then
  begin
    SSL_get_recv_max_early_data :=  @ERROR_SSL_get_recv_max_early_data;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_get_app_data := LoadLibSSLFunction('SSL_get_app_data');
  FuncLoadError := not assigned(SSL_get_app_data);
  if FuncLoadError then
  begin
    SSL_get_app_data := @COMPAT_SSL_get_app_data;
    if SSL_get_app_data_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get_app_data');
  end;

  SSL_set_app_data := LoadLibSSLFunction('SSL_set_app_data');
  FuncLoadError := not assigned(SSL_set_app_data);
  if FuncLoadError then
  begin
    SSL_set_app_data := @COMPAT_SSL_set_app_data;
    if SSL_set_app_data_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_set_app_data');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_in_init := LoadLibSSLFunction('SSL_in_init');
  FuncLoadError := not assigned(SSL_in_init);
  if FuncLoadError then
  begin
    SSL_in_init :=  @ERROR_SSL_in_init;
  end;

  SSL_in_before := LoadLibSSLFunction('SSL_in_before');
  FuncLoadError := not assigned(SSL_in_before);
  if FuncLoadError then
  begin
    SSL_in_before :=  @ERROR_SSL_in_before;
  end;

  SSL_is_init_finished := LoadLibSSLFunction('SSL_is_init_finished');
  FuncLoadError := not assigned(SSL_is_init_finished);
  if FuncLoadError then
  begin
    SSL_is_init_finished :=  @ERROR_SSL_is_init_finished;
  end;

  SSL_get_finished := LoadLibSSLFunction('SSL_get_finished');
  FuncLoadError := not assigned(SSL_get_finished);
  if FuncLoadError then
  begin
    SSL_get_finished :=  @ERROR_SSL_get_finished;
  end;

  SSL_get_peer_finished := LoadLibSSLFunction('SSL_get_peer_finished');
  FuncLoadError := not assigned(SSL_get_peer_finished);
  if FuncLoadError then
  begin
    SSL_get_peer_finished :=  @ERROR_SSL_get_peer_finished;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLeay_add_ssl_algorithms := LoadLibSSLFunction('SSLeay_add_ssl_algorithms');
  FuncLoadError := not assigned(SSLeay_add_ssl_algorithms);
  if FuncLoadError then
  begin
    SSLeay_add_ssl_algorithms := @COMPAT_SSLeay_add_ssl_algorithms;
    if SSLeay_add_ssl_algorithms_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSLeay_add_ssl_algorithms');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  BIO_f_ssl := LoadLibSSLFunction('BIO_f_ssl');
  FuncLoadError := not assigned(BIO_f_ssl);
  if FuncLoadError then
  begin
    BIO_f_ssl :=  @ERROR_BIO_f_ssl;
  end;

  BIO_new_ssl := LoadLibSSLFunction('BIO_new_ssl');
  FuncLoadError := not assigned(BIO_new_ssl);
  if FuncLoadError then
  begin
    BIO_new_ssl :=  @ERROR_BIO_new_ssl;
  end;

  BIO_new_ssl_connect := LoadLibSSLFunction('BIO_new_ssl_connect');
  FuncLoadError := not assigned(BIO_new_ssl_connect);
  if FuncLoadError then
  begin
    BIO_new_ssl_connect :=  @ERROR_BIO_new_ssl_connect;
  end;

  BIO_new_buffer_ssl_connect := LoadLibSSLFunction('BIO_new_buffer_ssl_connect');
  FuncLoadError := not assigned(BIO_new_buffer_ssl_connect);
  if FuncLoadError then
  begin
    BIO_new_buffer_ssl_connect :=  @ERROR_BIO_new_buffer_ssl_connect;
  end;

  BIO_ssl_copy_session_id := LoadLibSSLFunction('BIO_ssl_copy_session_id');
  FuncLoadError := not assigned(BIO_ssl_copy_session_id);
  if FuncLoadError then
  begin
    BIO_ssl_copy_session_id :=  @ERROR_BIO_ssl_copy_session_id;
  end;

  SSL_CTX_set_cipher_list := LoadLibSSLFunction('SSL_CTX_set_cipher_list');
  FuncLoadError := not assigned(SSL_CTX_set_cipher_list);
  if FuncLoadError then
  begin
    SSL_CTX_set_cipher_list :=  @ERROR_SSL_CTX_set_cipher_list;
  end;

  SSL_CTX_new := LoadLibSSLFunction('SSL_CTX_new');
  FuncLoadError := not assigned(SSL_CTX_new);
  if FuncLoadError then
  begin
    SSL_CTX_new :=  @ERROR_SSL_CTX_new;
  end;

  SSL_CTX_set_timeout := LoadLibSSLFunction('SSL_CTX_set_timeout');
  FuncLoadError := not assigned(SSL_CTX_set_timeout);
  if FuncLoadError then
  begin
    SSL_CTX_set_timeout :=  @ERROR_SSL_CTX_set_timeout;
  end;

  SSL_CTX_get_timeout := LoadLibSSLFunction('SSL_CTX_get_timeout');
  FuncLoadError := not assigned(SSL_CTX_get_timeout);
  if FuncLoadError then
  begin
    SSL_CTX_get_timeout :=  @ERROR_SSL_CTX_get_timeout;
  end;

  SSL_CTX_get_cert_store := LoadLibSSLFunction('SSL_CTX_get_cert_store');
  FuncLoadError := not assigned(SSL_CTX_get_cert_store);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_cert_store := @COMPAT_SSL_CTX_get_cert_store;
{$ELSE}
    SSL_CTX_get_cert_store :=  @ERROR_SSL_CTX_get_cert_store;
{$ENDIF}
  end;

  SSL_want := LoadLibSSLFunction('SSL_want');
  FuncLoadError := not assigned(SSL_want);
  if FuncLoadError then
  begin
    SSL_want :=  @ERROR_SSL_want;
  end;

  SSL_clear := LoadLibSSLFunction('SSL_clear');
  FuncLoadError := not assigned(SSL_clear);
  if FuncLoadError then
  begin
    SSL_clear :=  @ERROR_SSL_clear;
  end;

  BIO_ssl_shutdown := LoadLibSSLFunction('BIO_ssl_shutdown');
  FuncLoadError := not assigned(BIO_ssl_shutdown);
  if FuncLoadError then
  begin
    BIO_ssl_shutdown :=  @ERROR_BIO_ssl_shutdown;
  end;

  SSL_CTX_up_ref := LoadLibSSLFunction('SSL_CTX_up_ref');
  FuncLoadError := not assigned(SSL_CTX_up_ref);
  if FuncLoadError then
  begin
    SSL_CTX_up_ref :=  @ERROR_SSL_CTX_up_ref;
  end;

  SSL_CTX_free := LoadLibSSLFunction('SSL_CTX_free');
  FuncLoadError := not assigned(SSL_CTX_free);
  if FuncLoadError then
  begin
    SSL_CTX_free :=  @ERROR_SSL_CTX_free;
  end;

  SSL_CTX_set_cert_store := LoadLibSSLFunction('SSL_CTX_set_cert_store');
  FuncLoadError := not assigned(SSL_CTX_set_cert_store);
  if FuncLoadError then
  begin
    SSL_CTX_set_cert_store :=  @ERROR_SSL_CTX_set_cert_store;
  end;

  SSL_CTX_set1_cert_store := LoadLibSSLFunction('SSL_CTX_set1_cert_store');
  FuncLoadError := not assigned(SSL_CTX_set1_cert_store);
  if FuncLoadError then
  begin
    SSL_CTX_set1_cert_store :=  @ERROR_SSL_CTX_set1_cert_store;
  end;

  SSL_CTX_flush_sessions := LoadLibSSLFunction('SSL_CTX_flush_sessions');
  FuncLoadError := not assigned(SSL_CTX_flush_sessions);
  if FuncLoadError then
  begin
    SSL_CTX_flush_sessions :=  @ERROR_SSL_CTX_flush_sessions;
  end;

  SSL_get_current_cipher := LoadLibSSLFunction('SSL_get_current_cipher');
  FuncLoadError := not assigned(SSL_get_current_cipher);
  if FuncLoadError then
  begin
    SSL_get_current_cipher :=  @ERROR_SSL_get_current_cipher;
  end;

  SSL_get_pending_cipher := LoadLibSSLFunction('SSL_get_pending_cipher');
  FuncLoadError := not assigned(SSL_get_pending_cipher);
  if FuncLoadError then
  begin
    SSL_get_pending_cipher :=  @ERROR_SSL_get_pending_cipher;
  end;

  SSL_CIPHER_get_bits := LoadLibSSLFunction('SSL_CIPHER_get_bits');
  FuncLoadError := not assigned(SSL_CIPHER_get_bits);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_bits :=  @ERROR_SSL_CIPHER_get_bits;
  end;

  SSL_CIPHER_get_version := LoadLibSSLFunction('SSL_CIPHER_get_version');
  FuncLoadError := not assigned(SSL_CIPHER_get_version);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_version :=  @ERROR_SSL_CIPHER_get_version;
  end;

  SSL_CIPHER_get_name := LoadLibSSLFunction('SSL_CIPHER_get_name');
  FuncLoadError := not assigned(SSL_CIPHER_get_name);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_name :=  @ERROR_SSL_CIPHER_get_name;
  end;

  SSL_CIPHER_standard_name := LoadLibSSLFunction('SSL_CIPHER_standard_name');
  FuncLoadError := not assigned(SSL_CIPHER_standard_name);
  if FuncLoadError then
  begin
    SSL_CIPHER_standard_name :=  @ERROR_SSL_CIPHER_standard_name;
  end;

  OPENSSL_cipher_name := LoadLibSSLFunction('OPENSSL_cipher_name');
  FuncLoadError := not assigned(OPENSSL_cipher_name);
  if FuncLoadError then
  begin
    OPENSSL_cipher_name :=  @ERROR_OPENSSL_cipher_name;
  end;

  SSL_CIPHER_get_id := LoadLibSSLFunction('SSL_CIPHER_get_id');
  FuncLoadError := not assigned(SSL_CIPHER_get_id);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_id :=  @ERROR_SSL_CIPHER_get_id;
  end;

  SSL_CIPHER_get_protocol_id := LoadLibSSLFunction('SSL_CIPHER_get_protocol_id');
  FuncLoadError := not assigned(SSL_CIPHER_get_protocol_id);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_protocol_id :=  @ERROR_SSL_CIPHER_get_protocol_id;
  end;

  SSL_CIPHER_get_kx_nid := LoadLibSSLFunction('SSL_CIPHER_get_kx_nid');
  FuncLoadError := not assigned(SSL_CIPHER_get_kx_nid);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_kx_nid :=  @ERROR_SSL_CIPHER_get_kx_nid;
  end;

  SSL_CIPHER_get_auth_nid := LoadLibSSLFunction('SSL_CIPHER_get_auth_nid');
  FuncLoadError := not assigned(SSL_CIPHER_get_auth_nid);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_auth_nid :=  @ERROR_SSL_CIPHER_get_auth_nid;
  end;

  SSL_CIPHER_get_handshake_digest := LoadLibSSLFunction('SSL_CIPHER_get_handshake_digest');
  FuncLoadError := not assigned(SSL_CIPHER_get_handshake_digest);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_handshake_digest :=  @ERROR_SSL_CIPHER_get_handshake_digest;
  end;

  SSL_CIPHER_is_aead := LoadLibSSLFunction('SSL_CIPHER_is_aead');
  FuncLoadError := not assigned(SSL_CIPHER_is_aead);
  if FuncLoadError then
  begin
    SSL_CIPHER_is_aead :=  @ERROR_SSL_CIPHER_is_aead;
  end;

  SSL_get_fd := LoadLibSSLFunction('SSL_get_fd');
  FuncLoadError := not assigned(SSL_get_fd);
  if FuncLoadError then
  begin
    SSL_get_fd :=  @ERROR_SSL_get_fd;
  end;

  SSL_get_rfd := LoadLibSSLFunction('SSL_get_rfd');
  FuncLoadError := not assigned(SSL_get_rfd);
  if FuncLoadError then
  begin
    SSL_get_rfd :=  @ERROR_SSL_get_rfd;
  end;

  SSL_get_wfd := LoadLibSSLFunction('SSL_get_wfd');
  FuncLoadError := not assigned(SSL_get_wfd);
  if FuncLoadError then
  begin
    SSL_get_wfd :=  @ERROR_SSL_get_wfd;
  end;

  SSL_get_cipher_list := LoadLibSSLFunction('SSL_get_cipher_list');
  FuncLoadError := not assigned(SSL_get_cipher_list);
  if FuncLoadError then
  begin
    SSL_get_cipher_list :=  @ERROR_SSL_get_cipher_list;
  end;

  SSL_get_shared_ciphers := LoadLibSSLFunction('SSL_get_shared_ciphers');
  FuncLoadError := not assigned(SSL_get_shared_ciphers);
  if FuncLoadError then
  begin
    SSL_get_shared_ciphers :=  @ERROR_SSL_get_shared_ciphers;
  end;

  SSL_get_read_ahead := LoadLibSSLFunction('SSL_get_read_ahead');
  FuncLoadError := not assigned(SSL_get_read_ahead);
  if FuncLoadError then
  begin
    SSL_get_read_ahead :=  @ERROR_SSL_get_read_ahead;
  end;

  SSL_pending := LoadLibSSLFunction('SSL_pending');
  FuncLoadError := not assigned(SSL_pending);
  if FuncLoadError then
  begin
    SSL_pending :=  @ERROR_SSL_pending;
  end;

  SSL_has_pending := LoadLibSSLFunction('SSL_has_pending');
  FuncLoadError := not assigned(SSL_has_pending);
  if FuncLoadError then
  begin
    SSL_has_pending :=  @ERROR_SSL_has_pending;
  end;

  SSL_set_fd := LoadLibSSLFunction('SSL_set_fd');
  FuncLoadError := not assigned(SSL_set_fd);
  if FuncLoadError then
  begin
    SSL_set_fd :=  @ERROR_SSL_set_fd;
  end;

  SSL_set_rfd := LoadLibSSLFunction('SSL_set_rfd');
  FuncLoadError := not assigned(SSL_set_rfd);
  if FuncLoadError then
  begin
    SSL_set_rfd :=  @ERROR_SSL_set_rfd;
  end;

  SSL_set_wfd := LoadLibSSLFunction('SSL_set_wfd');
  FuncLoadError := not assigned(SSL_set_wfd);
  if FuncLoadError then
  begin
    SSL_set_wfd :=  @ERROR_SSL_set_wfd;
  end;

  SSL_set0_rbio := LoadLibSSLFunction('SSL_set0_rbio');
  FuncLoadError := not assigned(SSL_set0_rbio);
  if FuncLoadError then
  begin
    SSL_set0_rbio :=  @ERROR_SSL_set0_rbio;
  end;

  SSL_set0_wbio := LoadLibSSLFunction('SSL_set0_wbio');
  FuncLoadError := not assigned(SSL_set0_wbio);
  if FuncLoadError then
  begin
    SSL_set0_wbio :=  @ERROR_SSL_set0_wbio;
  end;

  SSL_set_bio := LoadLibSSLFunction('SSL_set_bio');
  FuncLoadError := not assigned(SSL_set_bio);
  if FuncLoadError then
  begin
    SSL_set_bio :=  @ERROR_SSL_set_bio;
  end;

  SSL_get_rbio := LoadLibSSLFunction('SSL_get_rbio');
  FuncLoadError := not assigned(SSL_get_rbio);
  if FuncLoadError then
  begin
    SSL_get_rbio :=  @ERROR_SSL_get_rbio;
  end;

  SSL_get_wbio := LoadLibSSLFunction('SSL_get_wbio');
  FuncLoadError := not assigned(SSL_get_wbio);
  if FuncLoadError then
  begin
    SSL_get_wbio :=  @ERROR_SSL_get_wbio;
  end;

  SSL_set_cipher_list := LoadLibSSLFunction('SSL_set_cipher_list');
  FuncLoadError := not assigned(SSL_set_cipher_list);
  if FuncLoadError then
  begin
    SSL_set_cipher_list :=  @ERROR_SSL_set_cipher_list;
  end;

  SSL_CTX_set_ciphersuites := LoadLibSSLFunction('SSL_CTX_set_ciphersuites');
  FuncLoadError := not assigned(SSL_CTX_set_ciphersuites);
  if FuncLoadError then
  begin
    SSL_CTX_set_ciphersuites :=  @ERROR_SSL_CTX_set_ciphersuites;
  end;

  SSL_set_ciphersuites := LoadLibSSLFunction('SSL_set_ciphersuites');
  FuncLoadError := not assigned(SSL_set_ciphersuites);
  if FuncLoadError then
  begin
    SSL_set_ciphersuites :=  @ERROR_SSL_set_ciphersuites;
  end;

  SSL_get_verify_mode := LoadLibSSLFunction('SSL_get_verify_mode');
  FuncLoadError := not assigned(SSL_get_verify_mode);
  if FuncLoadError then
  begin
    SSL_get_verify_mode :=  @ERROR_SSL_get_verify_mode;
  end;

  SSL_get_verify_depth := LoadLibSSLFunction('SSL_get_verify_depth');
  FuncLoadError := not assigned(SSL_get_verify_depth);
  if FuncLoadError then
  begin
    SSL_get_verify_depth :=  @ERROR_SSL_get_verify_depth;
  end;

  SSL_get_verify_callback := LoadLibSSLFunction('SSL_get_verify_callback');
  FuncLoadError := not assigned(SSL_get_verify_callback);
  if FuncLoadError then
  begin
    SSL_get_verify_callback :=  @ERROR_SSL_get_verify_callback;
  end;

  SSL_set_read_ahead := LoadLibSSLFunction('SSL_set_read_ahead');
  FuncLoadError := not assigned(SSL_set_read_ahead);
  if FuncLoadError then
  begin
    SSL_set_read_ahead :=  @ERROR_SSL_set_read_ahead;
  end;

  SSL_set_verify := LoadLibSSLFunction('SSL_set_verify');
  FuncLoadError := not assigned(SSL_set_verify);
  if FuncLoadError then
  begin
    SSL_set_verify :=  @ERROR_SSL_set_verify;
  end;

  SSL_set_verify_depth := LoadLibSSLFunction('SSL_set_verify_depth');
  FuncLoadError := not assigned(SSL_set_verify_depth);
  if FuncLoadError then
  begin
    SSL_set_verify_depth :=  @ERROR_SSL_set_verify_depth;
  end;

  SSL_use_RSAPrivateKey := LoadLibSSLFunction('SSL_use_RSAPrivateKey');
  FuncLoadError := not assigned(SSL_use_RSAPrivateKey);
  if FuncLoadError then
  begin
    SSL_use_RSAPrivateKey :=  @ERROR_SSL_use_RSAPrivateKey;
  end;

  SSL_use_RSAPrivateKey_ASN1 := LoadLibSSLFunction('SSL_use_RSAPrivateKey_ASN1');
  FuncLoadError := not assigned(SSL_use_RSAPrivateKey_ASN1);
  if FuncLoadError then
  begin
    SSL_use_RSAPrivateKey_ASN1 :=  @ERROR_SSL_use_RSAPrivateKey_ASN1;
  end;

  SSL_use_PrivateKey := LoadLibSSLFunction('SSL_use_PrivateKey');
  FuncLoadError := not assigned(SSL_use_PrivateKey);
  if FuncLoadError then
  begin
    SSL_use_PrivateKey :=  @ERROR_SSL_use_PrivateKey;
  end;

  SSL_use_PrivateKey_ASN1 := LoadLibSSLFunction('SSL_use_PrivateKey_ASN1');
  FuncLoadError := not assigned(SSL_use_PrivateKey_ASN1);
  if FuncLoadError then
  begin
    SSL_use_PrivateKey_ASN1 :=  @ERROR_SSL_use_PrivateKey_ASN1;
  end;

  SSL_use_certificate := LoadLibSSLFunction('SSL_use_certificate');
  FuncLoadError := not assigned(SSL_use_certificate);
  if FuncLoadError then
  begin
    SSL_use_certificate :=  @ERROR_SSL_use_certificate;
  end;

  SSL_use_certificate_ASN1 := LoadLibSSLFunction('SSL_use_certificate_ASN1');
  FuncLoadError := not assigned(SSL_use_certificate_ASN1);
  if FuncLoadError then
  begin
    SSL_use_certificate_ASN1 :=  @ERROR_SSL_use_certificate_ASN1;
  end;

  SSL_CTX_use_serverinfo := LoadLibSSLFunction('SSL_CTX_use_serverinfo');
  FuncLoadError := not assigned(SSL_CTX_use_serverinfo);
  if FuncLoadError then
  begin
    SSL_CTX_use_serverinfo :=  @ERROR_SSL_CTX_use_serverinfo;
  end;

  SSL_CTX_use_serverinfo_ex := LoadLibSSLFunction('SSL_CTX_use_serverinfo_ex');
  FuncLoadError := not assigned(SSL_CTX_use_serverinfo_ex);
  if FuncLoadError then
  begin
    SSL_CTX_use_serverinfo_ex :=  @ERROR_SSL_CTX_use_serverinfo_ex;
  end;

  SSL_CTX_use_serverinfo_file := LoadLibSSLFunction('SSL_CTX_use_serverinfo_file');
  FuncLoadError := not assigned(SSL_CTX_use_serverinfo_file);
  if FuncLoadError then
  begin
    SSL_CTX_use_serverinfo_file :=  @ERROR_SSL_CTX_use_serverinfo_file;
  end;

  SSL_use_RSAPrivateKey_file := LoadLibSSLFunction('SSL_use_RSAPrivateKey_file');
  FuncLoadError := not assigned(SSL_use_RSAPrivateKey_file);
  if FuncLoadError then
  begin
    SSL_use_RSAPrivateKey_file :=  @ERROR_SSL_use_RSAPrivateKey_file;
  end;

  SSL_use_PrivateKey_file := LoadLibSSLFunction('SSL_use_PrivateKey_file');
  FuncLoadError := not assigned(SSL_use_PrivateKey_file);
  if FuncLoadError then
  begin
    SSL_use_PrivateKey_file :=  @ERROR_SSL_use_PrivateKey_file;
  end;

  SSL_use_certificate_file := LoadLibSSLFunction('SSL_use_certificate_file');
  FuncLoadError := not assigned(SSL_use_certificate_file);
  if FuncLoadError then
  begin
    SSL_use_certificate_file :=  @ERROR_SSL_use_certificate_file;
  end;

  SSL_CTX_use_RSAPrivateKey_file := LoadLibSSLFunction('SSL_CTX_use_RSAPrivateKey_file');
  FuncLoadError := not assigned(SSL_CTX_use_RSAPrivateKey_file);
  if FuncLoadError then
  begin
    SSL_CTX_use_RSAPrivateKey_file :=  @ERROR_SSL_CTX_use_RSAPrivateKey_file;
  end;

  SSL_CTX_use_PrivateKey_file := LoadLibSSLFunction('SSL_CTX_use_PrivateKey_file');
  FuncLoadError := not assigned(SSL_CTX_use_PrivateKey_file);
  if FuncLoadError then
  begin
    SSL_CTX_use_PrivateKey_file :=  @ERROR_SSL_CTX_use_PrivateKey_file;
  end;

  SSL_CTX_use_certificate_file := LoadLibSSLFunction('SSL_CTX_use_certificate_file');
  FuncLoadError := not assigned(SSL_CTX_use_certificate_file);
  if FuncLoadError then
  begin
    SSL_CTX_use_certificate_file :=  @ERROR_SSL_CTX_use_certificate_file;
  end;

  SSL_CTX_use_certificate_chain_file := LoadLibSSLFunction('SSL_CTX_use_certificate_chain_file');
  FuncLoadError := not assigned(SSL_CTX_use_certificate_chain_file);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_use_certificate_chain_file := @COMPAT_SSL_CTX_use_certificate_chain_file;
{$ELSE}
    SSL_CTX_use_certificate_chain_file :=  @ERROR_SSL_CTX_use_certificate_chain_file;
{$ENDIF}
  end;

  SSL_use_certificate_chain_file := LoadLibSSLFunction('SSL_use_certificate_chain_file');
  FuncLoadError := not assigned(SSL_use_certificate_chain_file);
  if FuncLoadError then
  begin
    SSL_use_certificate_chain_file :=  @ERROR_SSL_use_certificate_chain_file;
  end;

  SSL_load_client_CA_file := LoadLibSSLFunction('SSL_load_client_CA_file');
  FuncLoadError := not assigned(SSL_load_client_CA_file);
  if FuncLoadError then
  begin
    SSL_load_client_CA_file :=  @ERROR_SSL_load_client_CA_file;
  end;

  SSL_add_file_cert_subjects_to_stack := LoadLibSSLFunction('SSL_add_file_cert_subjects_to_stack');
  FuncLoadError := not assigned(SSL_add_file_cert_subjects_to_stack);
  if FuncLoadError then
  begin
    SSL_add_file_cert_subjects_to_stack :=  @ERROR_SSL_add_file_cert_subjects_to_stack;
  end;

  SSL_add_dir_cert_subjects_to_stack := LoadLibSSLFunction('SSL_add_dir_cert_subjects_to_stack');
  FuncLoadError := not assigned(SSL_add_dir_cert_subjects_to_stack);
  if FuncLoadError then
  begin
    SSL_add_dir_cert_subjects_to_stack :=  @ERROR_SSL_add_dir_cert_subjects_to_stack;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_load_error_strings := LoadLibSSLFunction('SSL_load_error_strings');
  FuncLoadError := not assigned(SSL_load_error_strings);
  if FuncLoadError then
  begin
    SSL_load_error_strings := @COMPAT_SSL_load_error_strings;
    if SSL_load_error_strings_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_load_error_strings');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_state_string := LoadLibSSLFunction('SSL_state_string');
  FuncLoadError := not assigned(SSL_state_string);
  if FuncLoadError then
  begin
    SSL_state_string :=  @ERROR_SSL_state_string;
  end;

  SSL_rstate_string := LoadLibSSLFunction('SSL_rstate_string');
  FuncLoadError := not assigned(SSL_rstate_string);
  if FuncLoadError then
  begin
    SSL_rstate_string :=  @ERROR_SSL_rstate_string;
  end;

  SSL_state_string_long := LoadLibSSLFunction('SSL_state_string_long');
  FuncLoadError := not assigned(SSL_state_string_long);
  if FuncLoadError then
  begin
    SSL_state_string_long :=  @ERROR_SSL_state_string_long;
  end;

  SSL_rstate_string_long := LoadLibSSLFunction('SSL_rstate_string_long');
  FuncLoadError := not assigned(SSL_rstate_string_long);
  if FuncLoadError then
  begin
    SSL_rstate_string_long :=  @ERROR_SSL_rstate_string_long;
  end;

  SSL_SESSION_get_time := LoadLibSSLFunction('SSL_SESSION_get_time');
  FuncLoadError := not assigned(SSL_SESSION_get_time);
  if FuncLoadError then
  begin
    SSL_SESSION_get_time :=  @ERROR_SSL_SESSION_get_time;
  end;

  SSL_SESSION_set_time := LoadLibSSLFunction('SSL_SESSION_set_time');
  FuncLoadError := not assigned(SSL_SESSION_set_time);
  if FuncLoadError then
  begin
    SSL_SESSION_set_time :=  @ERROR_SSL_SESSION_set_time;
  end;

  SSL_SESSION_get_timeout := LoadLibSSLFunction('SSL_SESSION_get_timeout');
  FuncLoadError := not assigned(SSL_SESSION_get_timeout);
  if FuncLoadError then
  begin
    SSL_SESSION_get_timeout :=  @ERROR_SSL_SESSION_get_timeout;
  end;

  SSL_SESSION_set_timeout := LoadLibSSLFunction('SSL_SESSION_set_timeout');
  FuncLoadError := not assigned(SSL_SESSION_set_timeout);
  if FuncLoadError then
  begin
    SSL_SESSION_set_timeout :=  @ERROR_SSL_SESSION_set_timeout;
  end;

  SSL_SESSION_get_protocol_version := LoadLibSSLFunction('SSL_SESSION_get_protocol_version');
  FuncLoadError := not assigned(SSL_SESSION_get_protocol_version);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_SESSION_get_protocol_version := @COMPAT_SSL_SESSION_get_protocol_version;
{$ELSE}
    SSL_SESSION_get_protocol_version :=  @ERROR_SSL_SESSION_get_protocol_version;
{$ENDIF}
  end;

  SSL_SESSION_set_protocol_version := LoadLibSSLFunction('SSL_SESSION_set_protocol_version');
  FuncLoadError := not assigned(SSL_SESSION_set_protocol_version);
  if FuncLoadError then
  begin
    SSL_SESSION_set_protocol_version :=  @ERROR_SSL_SESSION_set_protocol_version;
  end;

  SSL_SESSION_get0_hostname := LoadLibSSLFunction('SSL_SESSION_get0_hostname');
  FuncLoadError := not assigned(SSL_SESSION_get0_hostname);
  if FuncLoadError then
  begin
    SSL_SESSION_get0_hostname :=  @ERROR_SSL_SESSION_get0_hostname;
  end;

  SSL_SESSION_set1_hostname := LoadLibSSLFunction('SSL_SESSION_set1_hostname');
  FuncLoadError := not assigned(SSL_SESSION_set1_hostname);
  if FuncLoadError then
  begin
    SSL_SESSION_set1_hostname :=  @ERROR_SSL_SESSION_set1_hostname;
  end;

  SSL_SESSION_get0_alpn_selected := LoadLibSSLFunction('SSL_SESSION_get0_alpn_selected');
  FuncLoadError := not assigned(SSL_SESSION_get0_alpn_selected);
  if FuncLoadError then
  begin
    SSL_SESSION_get0_alpn_selected :=  @ERROR_SSL_SESSION_get0_alpn_selected;
  end;

  SSL_SESSION_set1_alpn_selected := LoadLibSSLFunction('SSL_SESSION_set1_alpn_selected');
  FuncLoadError := not assigned(SSL_SESSION_set1_alpn_selected);
  if FuncLoadError then
  begin
    SSL_SESSION_set1_alpn_selected :=  @ERROR_SSL_SESSION_set1_alpn_selected;
  end;

  SSL_SESSION_get0_cipher := LoadLibSSLFunction('SSL_SESSION_get0_cipher');
  FuncLoadError := not assigned(SSL_SESSION_get0_cipher);
  if FuncLoadError then
  begin
    SSL_SESSION_get0_cipher :=  @ERROR_SSL_SESSION_get0_cipher;
  end;

  SSL_SESSION_set_cipher := LoadLibSSLFunction('SSL_SESSION_set_cipher');
  FuncLoadError := not assigned(SSL_SESSION_set_cipher);
  if FuncLoadError then
  begin
    SSL_SESSION_set_cipher :=  @ERROR_SSL_SESSION_set_cipher;
  end;

  SSL_SESSION_has_ticket := LoadLibSSLFunction('SSL_SESSION_has_ticket');
  FuncLoadError := not assigned(SSL_SESSION_has_ticket);
  if FuncLoadError then
  begin
    SSL_SESSION_has_ticket :=  @ERROR_SSL_SESSION_has_ticket;
  end;

  SSL_SESSION_get_ticket_lifetime_hint := LoadLibSSLFunction('SSL_SESSION_get_ticket_lifetime_hint');
  FuncLoadError := not assigned(SSL_SESSION_get_ticket_lifetime_hint);
  if FuncLoadError then
  begin
    SSL_SESSION_get_ticket_lifetime_hint :=  @ERROR_SSL_SESSION_get_ticket_lifetime_hint;
  end;

  SSL_SESSION_get0_ticket := LoadLibSSLFunction('SSL_SESSION_get0_ticket');
  FuncLoadError := not assigned(SSL_SESSION_get0_ticket);
  if FuncLoadError then
  begin
    SSL_SESSION_get0_ticket :=  @ERROR_SSL_SESSION_get0_ticket;
  end;

  SSL_SESSION_get_max_early_data := LoadLibSSLFunction('SSL_SESSION_get_max_early_data');
  FuncLoadError := not assigned(SSL_SESSION_get_max_early_data);
  if FuncLoadError then
  begin
    SSL_SESSION_get_max_early_data :=  @ERROR_SSL_SESSION_get_max_early_data;
  end;

  SSL_SESSION_set_max_early_data := LoadLibSSLFunction('SSL_SESSION_set_max_early_data');
  FuncLoadError := not assigned(SSL_SESSION_set_max_early_data);
  if FuncLoadError then
  begin
    SSL_SESSION_set_max_early_data :=  @ERROR_SSL_SESSION_set_max_early_data;
  end;

  SSL_copy_session_id := LoadLibSSLFunction('SSL_copy_session_id');
  FuncLoadError := not assigned(SSL_copy_session_id);
  if FuncLoadError then
  begin
    SSL_copy_session_id :=  @ERROR_SSL_copy_session_id;
  end;

  SSL_SESSION_get0_peer := LoadLibSSLFunction('SSL_SESSION_get0_peer');
  FuncLoadError := not assigned(SSL_SESSION_get0_peer);
  if FuncLoadError then
  begin
    SSL_SESSION_get0_peer :=  @ERROR_SSL_SESSION_get0_peer;
  end;

  SSL_SESSION_set1_id_context := LoadLibSSLFunction('SSL_SESSION_set1_id_context');
  FuncLoadError := not assigned(SSL_SESSION_set1_id_context);
  if FuncLoadError then
  begin
    SSL_SESSION_set1_id_context :=  @ERROR_SSL_SESSION_set1_id_context;
  end;

  SSL_SESSION_set1_id := LoadLibSSLFunction('SSL_SESSION_set1_id');
  FuncLoadError := not assigned(SSL_SESSION_set1_id);
  if FuncLoadError then
  begin
    SSL_SESSION_set1_id :=  @ERROR_SSL_SESSION_set1_id;
  end;

  SSL_SESSION_is_resumable := LoadLibSSLFunction('SSL_SESSION_is_resumable');
  FuncLoadError := not assigned(SSL_SESSION_is_resumable);
  if FuncLoadError then
  begin
    SSL_SESSION_is_resumable :=  @ERROR_SSL_SESSION_is_resumable;
  end;

  SSL_SESSION_new := LoadLibSSLFunction('SSL_SESSION_new');
  FuncLoadError := not assigned(SSL_SESSION_new);
  if FuncLoadError then
  begin
    SSL_SESSION_new :=  @ERROR_SSL_SESSION_new;
  end;

  SSL_SESSION_dup := LoadLibSSLFunction('SSL_SESSION_dup');
  FuncLoadError := not assigned(SSL_SESSION_dup);
  if FuncLoadError then
  begin
    SSL_SESSION_dup :=  @ERROR_SSL_SESSION_dup;
  end;

  SSL_SESSION_get_id := LoadLibSSLFunction('SSL_SESSION_get_id');
  FuncLoadError := not assigned(SSL_SESSION_get_id);
  if FuncLoadError then
  begin
    SSL_SESSION_get_id :=  @ERROR_SSL_SESSION_get_id;
  end;

  SSL_SESSION_get0_id_context := LoadLibSSLFunction('SSL_SESSION_get0_id_context');
  FuncLoadError := not assigned(SSL_SESSION_get0_id_context);
  if FuncLoadError then
  begin
    SSL_SESSION_get0_id_context :=  @ERROR_SSL_SESSION_get0_id_context;
  end;

  SSL_SESSION_get_compress_id := LoadLibSSLFunction('SSL_SESSION_get_compress_id');
  FuncLoadError := not assigned(SSL_SESSION_get_compress_id);
  if FuncLoadError then
  begin
    SSL_SESSION_get_compress_id :=  @ERROR_SSL_SESSION_get_compress_id;
  end;

  SSL_SESSION_print := LoadLibSSLFunction('SSL_SESSION_print');
  FuncLoadError := not assigned(SSL_SESSION_print);
  if FuncLoadError then
  begin
    SSL_SESSION_print :=  @ERROR_SSL_SESSION_print;
  end;

  SSL_SESSION_print_keylog := LoadLibSSLFunction('SSL_SESSION_print_keylog');
  FuncLoadError := not assigned(SSL_SESSION_print_keylog);
  if FuncLoadError then
  begin
    SSL_SESSION_print_keylog :=  @ERROR_SSL_SESSION_print_keylog;
  end;

  SSL_SESSION_up_ref := LoadLibSSLFunction('SSL_SESSION_up_ref');
  FuncLoadError := not assigned(SSL_SESSION_up_ref);
  if FuncLoadError then
  begin
    SSL_SESSION_up_ref :=  @ERROR_SSL_SESSION_up_ref;
  end;

  SSL_SESSION_free := LoadLibSSLFunction('SSL_SESSION_free');
  FuncLoadError := not assigned(SSL_SESSION_free);
  if FuncLoadError then
  begin
    SSL_SESSION_free :=  @ERROR_SSL_SESSION_free;
  end;

  SSL_set_session := LoadLibSSLFunction('SSL_set_session');
  FuncLoadError := not assigned(SSL_set_session);
  if FuncLoadError then
  begin
    SSL_set_session :=  @ERROR_SSL_set_session;
  end;

  SSL_CTX_add_session := LoadLibSSLFunction('SSL_CTX_add_session');
  FuncLoadError := not assigned(SSL_CTX_add_session);
  if FuncLoadError then
  begin
    SSL_CTX_add_session :=  @ERROR_SSL_CTX_add_session;
  end;

  SSL_CTX_remove_session := LoadLibSSLFunction('SSL_CTX_remove_session');
  FuncLoadError := not assigned(SSL_CTX_remove_session);
  if FuncLoadError then
  begin
    SSL_CTX_remove_session :=  @ERROR_SSL_CTX_remove_session;
  end;

  SSL_CTX_set_generate_session_id := LoadLibSSLFunction('SSL_CTX_set_generate_session_id');
  FuncLoadError := not assigned(SSL_CTX_set_generate_session_id);
  if FuncLoadError then
  begin
    SSL_CTX_set_generate_session_id :=  @ERROR_SSL_CTX_set_generate_session_id;
  end;

  SSL_set_generate_session_id := LoadLibSSLFunction('SSL_set_generate_session_id');
  FuncLoadError := not assigned(SSL_set_generate_session_id);
  if FuncLoadError then
  begin
    SSL_set_generate_session_id :=  @ERROR_SSL_set_generate_session_id;
  end;

  SSL_has_matching_session_id := LoadLibSSLFunction('SSL_has_matching_session_id');
  FuncLoadError := not assigned(SSL_has_matching_session_id);
  if FuncLoadError then
  begin
    SSL_has_matching_session_id :=  @ERROR_SSL_has_matching_session_id;
  end;

  d2i_SSL_SESSION := LoadLibSSLFunction('d2i_SSL_SESSION');
  FuncLoadError := not assigned(d2i_SSL_SESSION);
  if FuncLoadError then
  begin
    d2i_SSL_SESSION :=  @ERROR_d2i_SSL_SESSION;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_get_peer_certificate := LoadLibSSLFunction('SSL_get_peer_certificate');
  FuncLoadError := not assigned(SSL_get_peer_certificate);
  if FuncLoadError then
  begin
    SSL_get_peer_certificate := @COMPAT_SSL_get_peer_certificate;
    if SSL_get_peer_certificate_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get_peer_certificate');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CTX_get_verify_mode := LoadLibSSLFunction('SSL_CTX_get_verify_mode');
  FuncLoadError := not assigned(SSL_CTX_get_verify_mode);
  if FuncLoadError then
  begin
    SSL_CTX_get_verify_mode :=  @ERROR_SSL_CTX_get_verify_mode;
  end;

  SSL_CTX_get_verify_depth := LoadLibSSLFunction('SSL_CTX_get_verify_depth');
  FuncLoadError := not assigned(SSL_CTX_get_verify_depth);
  if FuncLoadError then
  begin
    SSL_CTX_get_verify_depth :=  @ERROR_SSL_CTX_get_verify_depth;
  end;

  SSL_CTX_get_verify_callback := LoadLibSSLFunction('SSL_CTX_get_verify_callback');
  FuncLoadError := not assigned(SSL_CTX_get_verify_callback);
  if FuncLoadError then
  begin
    SSL_CTX_get_verify_callback :=  @ERROR_SSL_CTX_get_verify_callback;
  end;

  SSL_CTX_set_verify := LoadLibSSLFunction('SSL_CTX_set_verify');
  FuncLoadError := not assigned(SSL_CTX_set_verify);
  if FuncLoadError then
  begin
    SSL_CTX_set_verify :=  @ERROR_SSL_CTX_set_verify;
  end;

  SSL_CTX_set_verify_depth := LoadLibSSLFunction('SSL_CTX_set_verify_depth');
  FuncLoadError := not assigned(SSL_CTX_set_verify_depth);
  if FuncLoadError then
  begin
    SSL_CTX_set_verify_depth :=  @ERROR_SSL_CTX_set_verify_depth;
  end;

  SSL_CTX_set_cert_verify_callback := LoadLibSSLFunction('SSL_CTX_set_cert_verify_callback');
  FuncLoadError := not assigned(SSL_CTX_set_cert_verify_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_cert_verify_callback :=  @ERROR_SSL_CTX_set_cert_verify_callback;
  end;

  SSL_CTX_set_cert_cb := LoadLibSSLFunction('SSL_CTX_set_cert_cb');
  FuncLoadError := not assigned(SSL_CTX_set_cert_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_cert_cb :=  @ERROR_SSL_CTX_set_cert_cb;
  end;

  SSL_CTX_use_RSAPrivateKey := LoadLibSSLFunction('SSL_CTX_use_RSAPrivateKey');
  FuncLoadError := not assigned(SSL_CTX_use_RSAPrivateKey);
  if FuncLoadError then
  begin
    SSL_CTX_use_RSAPrivateKey :=  @ERROR_SSL_CTX_use_RSAPrivateKey;
  end;

  SSL_CTX_use_RSAPrivateKey_ASN1 := LoadLibSSLFunction('SSL_CTX_use_RSAPrivateKey_ASN1');
  FuncLoadError := not assigned(SSL_CTX_use_RSAPrivateKey_ASN1);
  if FuncLoadError then
  begin
    SSL_CTX_use_RSAPrivateKey_ASN1 :=  @ERROR_SSL_CTX_use_RSAPrivateKey_ASN1;
  end;

  SSL_CTX_use_PrivateKey := LoadLibSSLFunction('SSL_CTX_use_PrivateKey');
  FuncLoadError := not assigned(SSL_CTX_use_PrivateKey);
  if FuncLoadError then
  begin
    SSL_CTX_use_PrivateKey :=  @ERROR_SSL_CTX_use_PrivateKey;
  end;

  SSL_CTX_use_PrivateKey_ASN1 := LoadLibSSLFunction('SSL_CTX_use_PrivateKey_ASN1');
  FuncLoadError := not assigned(SSL_CTX_use_PrivateKey_ASN1);
  if FuncLoadError then
  begin
    SSL_CTX_use_PrivateKey_ASN1 :=  @ERROR_SSL_CTX_use_PrivateKey_ASN1;
  end;

  SSL_CTX_use_certificate := LoadLibSSLFunction('SSL_CTX_use_certificate');
  FuncLoadError := not assigned(SSL_CTX_use_certificate);
  if FuncLoadError then
  begin
    SSL_CTX_use_certificate :=  @ERROR_SSL_CTX_use_certificate;
  end;

  SSL_CTX_use_certificate_ASN1 := LoadLibSSLFunction('SSL_CTX_use_certificate_ASN1');
  FuncLoadError := not assigned(SSL_CTX_use_certificate_ASN1);
  if FuncLoadError then
  begin
    SSL_CTX_use_certificate_ASN1 :=  @ERROR_SSL_CTX_use_certificate_ASN1;
  end;

  SSL_CTX_set_default_passwd_cb := LoadLibSSLFunction('SSL_CTX_set_default_passwd_cb');
  FuncLoadError := not assigned(SSL_CTX_set_default_passwd_cb);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_set_default_passwd_cb := @COMPAT_SSL_CTX_set_default_passwd_cb;
{$ELSE}
    SSL_CTX_set_default_passwd_cb :=  @ERROR_SSL_CTX_set_default_passwd_cb;
{$ENDIF}
  end;

  SSL_CTX_set_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_CTX_set_default_passwd_cb_userdata');
  FuncLoadError := not assigned(SSL_CTX_set_default_passwd_cb_userdata);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_set_default_passwd_cb_userdata := @COMPAT_SSL_CTX_set_default_passwd_cb_userdata;
{$ELSE}
    SSL_CTX_set_default_passwd_cb_userdata :=  @ERROR_SSL_CTX_set_default_passwd_cb_userdata;
{$ENDIF}
  end;

  SSL_CTX_get_default_passwd_cb := LoadLibSSLFunction('SSL_CTX_get_default_passwd_cb');
  FuncLoadError := not assigned(SSL_CTX_get_default_passwd_cb);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_default_passwd_cb := @COMPAT_SSL_CTX_get_default_passwd_cb;
{$ELSE}
    SSL_CTX_get_default_passwd_cb :=  @ERROR_SSL_CTX_get_default_passwd_cb;
{$ENDIF}
  end;

  SSL_CTX_get_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_CTX_get_default_passwd_cb_userdata');
  FuncLoadError := not assigned(SSL_CTX_get_default_passwd_cb_userdata);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_default_passwd_cb_userdata := @COMPAT_SSL_CTX_get_default_passwd_cb_userdata;
{$ELSE}
    SSL_CTX_get_default_passwd_cb_userdata :=  @ERROR_SSL_CTX_get_default_passwd_cb_userdata;
{$ENDIF}
  end;

  SSL_set_default_passwd_cb := LoadLibSSLFunction('SSL_set_default_passwd_cb');
  FuncLoadError := not assigned(SSL_set_default_passwd_cb);
  if FuncLoadError then
  begin
    SSL_set_default_passwd_cb :=  @ERROR_SSL_set_default_passwd_cb;
  end;

  SSL_set_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_set_default_passwd_cb_userdata');
  FuncLoadError := not assigned(SSL_set_default_passwd_cb_userdata);
  if FuncLoadError then
  begin
    SSL_set_default_passwd_cb_userdata :=  @ERROR_SSL_set_default_passwd_cb_userdata;
  end;

  SSL_get_default_passwd_cb := LoadLibSSLFunction('SSL_get_default_passwd_cb');
  FuncLoadError := not assigned(SSL_get_default_passwd_cb);
  if FuncLoadError then
  begin
    SSL_get_default_passwd_cb :=  @ERROR_SSL_get_default_passwd_cb;
  end;

  SSL_get_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_get_default_passwd_cb_userdata');
  FuncLoadError := not assigned(SSL_get_default_passwd_cb_userdata);
  if FuncLoadError then
  begin
    SSL_get_default_passwd_cb_userdata :=  @ERROR_SSL_get_default_passwd_cb_userdata;
  end;

  SSL_CTX_check_private_key := LoadLibSSLFunction('SSL_CTX_check_private_key');
  FuncLoadError := not assigned(SSL_CTX_check_private_key);
  if FuncLoadError then
  begin
    SSL_CTX_check_private_key :=  @ERROR_SSL_CTX_check_private_key;
  end;

  SSL_check_private_key := LoadLibSSLFunction('SSL_check_private_key');
  FuncLoadError := not assigned(SSL_check_private_key);
  if FuncLoadError then
  begin
    SSL_check_private_key :=  @ERROR_SSL_check_private_key;
  end;

  SSL_CTX_set_session_id_context := LoadLibSSLFunction('SSL_CTX_set_session_id_context');
  FuncLoadError := not assigned(SSL_CTX_set_session_id_context);
  if FuncLoadError then
  begin
    SSL_CTX_set_session_id_context :=  @ERROR_SSL_CTX_set_session_id_context;
  end;

  SSL_new := LoadLibSSLFunction('SSL_new');
  FuncLoadError := not assigned(SSL_new);
  if FuncLoadError then
  begin
    SSL_new :=  @ERROR_SSL_new;
  end;

  SSL_up_ref := LoadLibSSLFunction('SSL_up_ref');
  FuncLoadError := not assigned(SSL_up_ref);
  if FuncLoadError then
  begin
    SSL_up_ref :=  @ERROR_SSL_up_ref;
  end;

  SSL_is_dtls := LoadLibSSLFunction('SSL_is_dtls');
  FuncLoadError := not assigned(SSL_is_dtls);
  if FuncLoadError then
  begin
    SSL_is_dtls :=  @ERROR_SSL_is_dtls;
  end;

  SSL_set_session_id_context := LoadLibSSLFunction('SSL_set_session_id_context');
  FuncLoadError := not assigned(SSL_set_session_id_context);
  if FuncLoadError then
  begin
    SSL_set_session_id_context :=  @ERROR_SSL_set_session_id_context;
  end;

  SSL_CTX_set_purpose := LoadLibSSLFunction('SSL_CTX_set_purpose');
  FuncLoadError := not assigned(SSL_CTX_set_purpose);
  if FuncLoadError then
  begin
    SSL_CTX_set_purpose :=  @ERROR_SSL_CTX_set_purpose;
  end;

  SSL_set_purpose := LoadLibSSLFunction('SSL_set_purpose');
  FuncLoadError := not assigned(SSL_set_purpose);
  if FuncLoadError then
  begin
    SSL_set_purpose :=  @ERROR_SSL_set_purpose;
  end;

  SSL_CTX_set_trust := LoadLibSSLFunction('SSL_CTX_set_trust');
  FuncLoadError := not assigned(SSL_CTX_set_trust);
  if FuncLoadError then
  begin
    SSL_CTX_set_trust :=  @ERROR_SSL_CTX_set_trust;
  end;

  SSL_set_trust := LoadLibSSLFunction('SSL_set_trust');
  FuncLoadError := not assigned(SSL_set_trust);
  if FuncLoadError then
  begin
    SSL_set_trust :=  @ERROR_SSL_set_trust;
  end;

  SSL_set1_host := LoadLibSSLFunction('SSL_set1_host');
  FuncLoadError := not assigned(SSL_set1_host);
  if FuncLoadError then
  begin
    SSL_set1_host :=  @ERROR_SSL_set1_host;
  end;

  SSL_add1_host := LoadLibSSLFunction('SSL_add1_host');
  FuncLoadError := not assigned(SSL_add1_host);
  if FuncLoadError then
  begin
    SSL_add1_host :=  @ERROR_SSL_add1_host;
  end;

  SSL_get0_peername := LoadLibSSLFunction('SSL_get0_peername');
  FuncLoadError := not assigned(SSL_get0_peername);
  if FuncLoadError then
  begin
    SSL_get0_peername :=  @ERROR_SSL_get0_peername;
  end;

  SSL_set_hostflags := LoadLibSSLFunction('SSL_set_hostflags');
  FuncLoadError := not assigned(SSL_set_hostflags);
  if FuncLoadError then
  begin
    SSL_set_hostflags :=  @ERROR_SSL_set_hostflags;
  end;

  SSL_CTX_dane_enable := LoadLibSSLFunction('SSL_CTX_dane_enable');
  FuncLoadError := not assigned(SSL_CTX_dane_enable);
  if FuncLoadError then
  begin
    SSL_CTX_dane_enable :=  @ERROR_SSL_CTX_dane_enable;
  end;

  SSL_CTX_dane_mtype_set := LoadLibSSLFunction('SSL_CTX_dane_mtype_set');
  FuncLoadError := not assigned(SSL_CTX_dane_mtype_set);
  if FuncLoadError then
  begin
    SSL_CTX_dane_mtype_set :=  @ERROR_SSL_CTX_dane_mtype_set;
  end;

  SSL_dane_enable := LoadLibSSLFunction('SSL_dane_enable');
  FuncLoadError := not assigned(SSL_dane_enable);
  if FuncLoadError then
  begin
    SSL_dane_enable :=  @ERROR_SSL_dane_enable;
  end;

  SSL_dane_tlsa_add := LoadLibSSLFunction('SSL_dane_tlsa_add');
  FuncLoadError := not assigned(SSL_dane_tlsa_add);
  if FuncLoadError then
  begin
    SSL_dane_tlsa_add :=  @ERROR_SSL_dane_tlsa_add;
  end;

  SSL_get0_dane_authority := LoadLibSSLFunction('SSL_get0_dane_authority');
  FuncLoadError := not assigned(SSL_get0_dane_authority);
  if FuncLoadError then
  begin
    SSL_get0_dane_authority :=  @ERROR_SSL_get0_dane_authority;
  end;

  SSL_get0_dane_tlsa := LoadLibSSLFunction('SSL_get0_dane_tlsa');
  FuncLoadError := not assigned(SSL_get0_dane_tlsa);
  if FuncLoadError then
  begin
    SSL_get0_dane_tlsa :=  @ERROR_SSL_get0_dane_tlsa;
  end;

  SSL_get0_dane := LoadLibSSLFunction('SSL_get0_dane');
  FuncLoadError := not assigned(SSL_get0_dane);
  if FuncLoadError then
  begin
    SSL_get0_dane :=  @ERROR_SSL_get0_dane;
  end;

  SSL_CTX_dane_set_flags := LoadLibSSLFunction('SSL_CTX_dane_set_flags');
  FuncLoadError := not assigned(SSL_CTX_dane_set_flags);
  if FuncLoadError then
  begin
    SSL_CTX_dane_set_flags :=  @ERROR_SSL_CTX_dane_set_flags;
  end;

  SSL_CTX_dane_clear_flags := LoadLibSSLFunction('SSL_CTX_dane_clear_flags');
  FuncLoadError := not assigned(SSL_CTX_dane_clear_flags);
  if FuncLoadError then
  begin
    SSL_CTX_dane_clear_flags :=  @ERROR_SSL_CTX_dane_clear_flags;
  end;

  SSL_dane_set_flags := LoadLibSSLFunction('SSL_dane_set_flags');
  FuncLoadError := not assigned(SSL_dane_set_flags);
  if FuncLoadError then
  begin
    SSL_dane_set_flags :=  @ERROR_SSL_dane_set_flags;
  end;

  SSL_dane_clear_flags := LoadLibSSLFunction('SSL_dane_clear_flags');
  FuncLoadError := not assigned(SSL_dane_clear_flags);
  if FuncLoadError then
  begin
    SSL_dane_clear_flags :=  @ERROR_SSL_dane_clear_flags;
  end;

  SSL_CTX_set1_param := LoadLibSSLFunction('SSL_CTX_set1_param');
  FuncLoadError := not assigned(SSL_CTX_set1_param);
  if FuncLoadError then
  begin
    SSL_CTX_set1_param :=  @ERROR_SSL_CTX_set1_param;
  end;

  SSL_set1_param := LoadLibSSLFunction('SSL_set1_param');
  FuncLoadError := not assigned(SSL_set1_param);
  if FuncLoadError then
  begin
    SSL_set1_param :=  @ERROR_SSL_set1_param;
  end;

  SSL_CTX_get0_param := LoadLibSSLFunction('SSL_CTX_get0_param');
  FuncLoadError := not assigned(SSL_CTX_get0_param);
  if FuncLoadError then
  begin
    SSL_CTX_get0_param :=  @ERROR_SSL_CTX_get0_param;
  end;

  SSL_get0_param := LoadLibSSLFunction('SSL_get0_param');
  FuncLoadError := not assigned(SSL_get0_param);
  if FuncLoadError then
  begin
    SSL_get0_param :=  @ERROR_SSL_get0_param;
  end;

  SSL_CTX_set_srp_username := LoadLibSSLFunction('SSL_CTX_set_srp_username');
  FuncLoadError := not assigned(SSL_CTX_set_srp_username);
  if FuncLoadError then
  begin
    SSL_CTX_set_srp_username :=  @ERROR_SSL_CTX_set_srp_username;
  end;

  SSL_CTX_set_srp_password := LoadLibSSLFunction('SSL_CTX_set_srp_password');
  FuncLoadError := not assigned(SSL_CTX_set_srp_password);
  if FuncLoadError then
  begin
    SSL_CTX_set_srp_password :=  @ERROR_SSL_CTX_set_srp_password;
  end;

  SSL_CTX_set_srp_strength := LoadLibSSLFunction('SSL_CTX_set_srp_strength');
  FuncLoadError := not assigned(SSL_CTX_set_srp_strength);
  if FuncLoadError then
  begin
    SSL_CTX_set_srp_strength :=  @ERROR_SSL_CTX_set_srp_strength;
  end;

  SSL_CTX_set_srp_client_pwd_callback := LoadLibSSLFunction('SSL_CTX_set_srp_client_pwd_callback');
  FuncLoadError := not assigned(SSL_CTX_set_srp_client_pwd_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_srp_client_pwd_callback :=  @ERROR_SSL_CTX_set_srp_client_pwd_callback;
  end;

  SSL_CTX_set_srp_verify_param_callback := LoadLibSSLFunction('SSL_CTX_set_srp_verify_param_callback');
  FuncLoadError := not assigned(SSL_CTX_set_srp_verify_param_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_srp_verify_param_callback :=  @ERROR_SSL_CTX_set_srp_verify_param_callback;
  end;

  SSL_CTX_set_srp_username_callback := LoadLibSSLFunction('SSL_CTX_set_srp_username_callback');
  FuncLoadError := not assigned(SSL_CTX_set_srp_username_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_srp_username_callback :=  @ERROR_SSL_CTX_set_srp_username_callback;
  end;

  SSL_CTX_set_srp_cb_arg := LoadLibSSLFunction('SSL_CTX_set_srp_cb_arg');
  FuncLoadError := not assigned(SSL_CTX_set_srp_cb_arg);
  if FuncLoadError then
  begin
    SSL_CTX_set_srp_cb_arg :=  @ERROR_SSL_CTX_set_srp_cb_arg;
  end;

  SSL_set_srp_server_param := LoadLibSSLFunction('SSL_set_srp_server_param');
  FuncLoadError := not assigned(SSL_set_srp_server_param);
  if FuncLoadError then
  begin
    SSL_set_srp_server_param :=  @ERROR_SSL_set_srp_server_param;
  end;

  SSL_set_srp_server_param_pw := LoadLibSSLFunction('SSL_set_srp_server_param_pw');
  FuncLoadError := not assigned(SSL_set_srp_server_param_pw);
  if FuncLoadError then
  begin
    SSL_set_srp_server_param_pw :=  @ERROR_SSL_set_srp_server_param_pw;
  end;

  SSL_CTX_set_client_hello_cb := LoadLibSSLFunction('SSL_CTX_set_client_hello_cb');
  FuncLoadError := not assigned(SSL_CTX_set_client_hello_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_client_hello_cb :=  @ERROR_SSL_CTX_set_client_hello_cb;
  end;

  SSL_client_hello_isv2 := LoadLibSSLFunction('SSL_client_hello_isv2');
  FuncLoadError := not assigned(SSL_client_hello_isv2);
  if FuncLoadError then
  begin
    SSL_client_hello_isv2 :=  @ERROR_SSL_client_hello_isv2;
  end;

  SSL_client_hello_get0_legacy_version := LoadLibSSLFunction('SSL_client_hello_get0_legacy_version');
  FuncLoadError := not assigned(SSL_client_hello_get0_legacy_version);
  if FuncLoadError then
  begin
    SSL_client_hello_get0_legacy_version :=  @ERROR_SSL_client_hello_get0_legacy_version;
  end;

  SSL_client_hello_get0_random := LoadLibSSLFunction('SSL_client_hello_get0_random');
  FuncLoadError := not assigned(SSL_client_hello_get0_random);
  if FuncLoadError then
  begin
    SSL_client_hello_get0_random :=  @ERROR_SSL_client_hello_get0_random;
  end;

  SSL_client_hello_get0_session_id := LoadLibSSLFunction('SSL_client_hello_get0_session_id');
  FuncLoadError := not assigned(SSL_client_hello_get0_session_id);
  if FuncLoadError then
  begin
    SSL_client_hello_get0_session_id :=  @ERROR_SSL_client_hello_get0_session_id;
  end;

  SSL_client_hello_get0_ciphers := LoadLibSSLFunction('SSL_client_hello_get0_ciphers');
  FuncLoadError := not assigned(SSL_client_hello_get0_ciphers);
  if FuncLoadError then
  begin
    SSL_client_hello_get0_ciphers :=  @ERROR_SSL_client_hello_get0_ciphers;
  end;

  SSL_client_hello_get0_compression_methods := LoadLibSSLFunction('SSL_client_hello_get0_compression_methods');
  FuncLoadError := not assigned(SSL_client_hello_get0_compression_methods);
  if FuncLoadError then
  begin
    SSL_client_hello_get0_compression_methods :=  @ERROR_SSL_client_hello_get0_compression_methods;
  end;

  SSL_client_hello_get1_extensions_present := LoadLibSSLFunction('SSL_client_hello_get1_extensions_present');
  FuncLoadError := not assigned(SSL_client_hello_get1_extensions_present);
  if FuncLoadError then
  begin
    SSL_client_hello_get1_extensions_present :=  @ERROR_SSL_client_hello_get1_extensions_present;
  end;

  SSL_client_hello_get0_ext := LoadLibSSLFunction('SSL_client_hello_get0_ext');
  FuncLoadError := not assigned(SSL_client_hello_get0_ext);
  if FuncLoadError then
  begin
    SSL_client_hello_get0_ext :=  @ERROR_SSL_client_hello_get0_ext;
  end;

  SSL_certs_clear := LoadLibSSLFunction('SSL_certs_clear');
  FuncLoadError := not assigned(SSL_certs_clear);
  if FuncLoadError then
  begin
    SSL_certs_clear :=  @ERROR_SSL_certs_clear;
  end;

  SSL_free := LoadLibSSLFunction('SSL_free');
  FuncLoadError := not assigned(SSL_free);
  if FuncLoadError then
  begin
    SSL_free :=  @ERROR_SSL_free;
  end;

  SSL_waiting_for_async := LoadLibSSLFunction('SSL_waiting_for_async');
  FuncLoadError := not assigned(SSL_waiting_for_async);
  if FuncLoadError then
  begin
    SSL_waiting_for_async :=  @ERROR_SSL_waiting_for_async;
  end;

  SSL_get_all_async_fds := LoadLibSSLFunction('SSL_get_all_async_fds');
  FuncLoadError := not assigned(SSL_get_all_async_fds);
  if FuncLoadError then
  begin
    SSL_get_all_async_fds :=  @ERROR_SSL_get_all_async_fds;
  end;

  SSL_get_changed_async_fds := LoadLibSSLFunction('SSL_get_changed_async_fds');
  FuncLoadError := not assigned(SSL_get_changed_async_fds);
  if FuncLoadError then
  begin
    SSL_get_changed_async_fds :=  @ERROR_SSL_get_changed_async_fds;
  end;

  SSL_accept := LoadLibSSLFunction('SSL_accept');
  FuncLoadError := not assigned(SSL_accept);
  if FuncLoadError then
  begin
    SSL_accept :=  @ERROR_SSL_accept;
  end;

  SSL_stateless := LoadLibSSLFunction('SSL_stateless');
  FuncLoadError := not assigned(SSL_stateless);
  if FuncLoadError then
  begin
    SSL_stateless :=  @ERROR_SSL_stateless;
  end;

  SSL_connect := LoadLibSSLFunction('SSL_connect');
  FuncLoadError := not assigned(SSL_connect);
  if FuncLoadError then
  begin
    SSL_connect :=  @ERROR_SSL_connect;
  end;

  SSL_read := LoadLibSSLFunction('SSL_read');
  FuncLoadError := not assigned(SSL_read);
  if FuncLoadError then
  begin
    SSL_read :=  @ERROR_SSL_read;
  end;

  SSL_read_ex := LoadLibSSLFunction('SSL_read_ex');
  FuncLoadError := not assigned(SSL_read_ex);
  if FuncLoadError then
  begin
    SSL_read_ex :=  @ERROR_SSL_read_ex;
  end;

  SSL_read_early_data := LoadLibSSLFunction('SSL_read_early_data');
  FuncLoadError := not assigned(SSL_read_early_data);
  if FuncLoadError then
  begin
    SSL_read_early_data :=  @ERROR_SSL_read_early_data;
  end;

  SSL_peek := LoadLibSSLFunction('SSL_peek');
  FuncLoadError := not assigned(SSL_peek);
  if FuncLoadError then
  begin
    SSL_peek :=  @ERROR_SSL_peek;
  end;

  SSL_peek_ex := LoadLibSSLFunction('SSL_peek_ex');
  FuncLoadError := not assigned(SSL_peek_ex);
  if FuncLoadError then
  begin
    SSL_peek_ex :=  @ERROR_SSL_peek_ex;
  end;

  SSL_write := LoadLibSSLFunction('SSL_write');
  FuncLoadError := not assigned(SSL_write);
  if FuncLoadError then
  begin
    SSL_write :=  @ERROR_SSL_write;
  end;

  SSL_write_ex := LoadLibSSLFunction('SSL_write_ex');
  FuncLoadError := not assigned(SSL_write_ex);
  if FuncLoadError then
  begin
    SSL_write_ex :=  @ERROR_SSL_write_ex;
  end;

  SSL_write_early_data := LoadLibSSLFunction('SSL_write_early_data');
  FuncLoadError := not assigned(SSL_write_early_data);
  if FuncLoadError then
  begin
    SSL_write_early_data :=  @ERROR_SSL_write_early_data;
  end;

  SSL_callback_ctrl := LoadLibSSLFunction('SSL_callback_ctrl');
  FuncLoadError := not assigned(SSL_callback_ctrl);
  if FuncLoadError then
  begin
    SSL_callback_ctrl :=  @ERROR_SSL_callback_ctrl;
  end;

  SSL_ctrl := LoadLibSSLFunction('SSL_ctrl');
  FuncLoadError := not assigned(SSL_ctrl);
  if FuncLoadError then
  begin
    SSL_ctrl :=  @ERROR_SSL_ctrl;
  end;

  SSL_CTX_ctrl := LoadLibSSLFunction('SSL_CTX_ctrl');
  FuncLoadError := not assigned(SSL_CTX_ctrl);
  if FuncLoadError then
  begin
    SSL_CTX_ctrl :=  @ERROR_SSL_CTX_ctrl;
  end;

  SSL_CTX_callback_ctrl := LoadLibSSLFunction('SSL_CTX_callback_ctrl');
  FuncLoadError := not assigned(SSL_CTX_callback_ctrl);
  if FuncLoadError then
  begin
    SSL_CTX_callback_ctrl :=  @ERROR_SSL_CTX_callback_ctrl;
  end;

  SSL_get_early_data_status := LoadLibSSLFunction('SSL_get_early_data_status');
  FuncLoadError := not assigned(SSL_get_early_data_status);
  if FuncLoadError then
  begin
    SSL_get_early_data_status :=  @ERROR_SSL_get_early_data_status;
  end;

  SSL_get_error := LoadLibSSLFunction('SSL_get_error');
  FuncLoadError := not assigned(SSL_get_error);
  if FuncLoadError then
  begin
    SSL_get_error :=  @ERROR_SSL_get_error;
  end;

  SSL_get_version := LoadLibSSLFunction('SSL_get_version');
  FuncLoadError := not assigned(SSL_get_version);
  if FuncLoadError then
  begin
    SSL_get_version :=  @ERROR_SSL_get_version;
  end;

  SSL_CTX_set_ssl_version := LoadLibSSLFunction('SSL_CTX_set_ssl_version');
  FuncLoadError := not assigned(SSL_CTX_set_ssl_version);
  if FuncLoadError then
  begin
    SSL_CTX_set_ssl_version :=  @ERROR_SSL_CTX_set_ssl_version;
  end;

  TLS_method := LoadLibSSLFunction('TLS_method');
  FuncLoadError := not assigned(TLS_method);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    TLS_method := @COMPAT_TLS_method;
{$ELSE}
    TLS_method :=  @ERROR_TLS_method;
{$ENDIF}
  end;

  TLS_server_method := LoadLibSSLFunction('TLS_server_method');
  FuncLoadError := not assigned(TLS_server_method);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    TLS_server_method := @COMPAT_TLS_server_method;
{$ELSE}
    TLS_server_method :=  @ERROR_TLS_server_method;
{$ENDIF}
  end;

  TLS_client_method := LoadLibSSLFunction('TLS_client_method');
  FuncLoadError := not assigned(TLS_client_method);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    TLS_client_method := @COMPAT_TLS_client_method;
{$ELSE}
    TLS_client_method :=  @ERROR_TLS_client_method;
{$ENDIF}
  end;

  SSL_do_handshake := LoadLibSSLFunction('SSL_do_handshake');
  FuncLoadError := not assigned(SSL_do_handshake);
  if FuncLoadError then
  begin
    SSL_do_handshake :=  @ERROR_SSL_do_handshake;
  end;

  SSL_key_update := LoadLibSSLFunction('SSL_key_update');
  FuncLoadError := not assigned(SSL_key_update);
  if FuncLoadError then
  begin
    SSL_key_update :=  @ERROR_SSL_key_update;
  end;

  SSL_get_key_update_type := LoadLibSSLFunction('SSL_get_key_update_type');
  FuncLoadError := not assigned(SSL_get_key_update_type);
  if FuncLoadError then
  begin
    SSL_get_key_update_type :=  @ERROR_SSL_get_key_update_type;
  end;

  SSL_renegotiate := LoadLibSSLFunction('SSL_renegotiate');
  FuncLoadError := not assigned(SSL_renegotiate);
  if FuncLoadError then
  begin
    SSL_renegotiate :=  @ERROR_SSL_renegotiate;
  end;

  SSL_renegotiate_abbreviated := LoadLibSSLFunction('SSL_renegotiate_abbreviated');
  FuncLoadError := not assigned(SSL_renegotiate_abbreviated);
  if FuncLoadError then
  begin
    SSL_renegotiate_abbreviated :=  @ERROR_SSL_renegotiate_abbreviated;
  end;

  SSL_new_session_ticket := LoadLibSSLFunction('SSL_new_session_ticket');
  FuncLoadError := not assigned(SSL_new_session_ticket);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_new_session_ticket := @COMPAT_SSL_new_session_ticket;
{$ELSE}
    SSL_new_session_ticket :=  @ERROR_SSL_new_session_ticket;
{$ENDIF}
  end;

  SSL_shutdown := LoadLibSSLFunction('SSL_shutdown');
  FuncLoadError := not assigned(SSL_shutdown);
  if FuncLoadError then
  begin
    SSL_shutdown :=  @ERROR_SSL_shutdown;
  end;

  SSL_CTX_set_post_handshake_auth := LoadLibSSLFunction('SSL_CTX_set_post_handshake_auth');
  FuncLoadError := not assigned(SSL_CTX_set_post_handshake_auth);
  if FuncLoadError then
  begin
    SSL_CTX_set_post_handshake_auth :=  @ERROR_SSL_CTX_set_post_handshake_auth;
  end;

  SSL_set_post_handshake_auth := LoadLibSSLFunction('SSL_set_post_handshake_auth');
  FuncLoadError := not assigned(SSL_set_post_handshake_auth);
  if FuncLoadError then
  begin
    SSL_set_post_handshake_auth :=  @ERROR_SSL_set_post_handshake_auth;
  end;

  SSL_renegotiate_pending := LoadLibSSLFunction('SSL_renegotiate_pending');
  FuncLoadError := not assigned(SSL_renegotiate_pending);
  if FuncLoadError then
  begin
    SSL_renegotiate_pending :=  @ERROR_SSL_renegotiate_pending;
  end;

  SSL_verify_client_post_handshake := LoadLibSSLFunction('SSL_verify_client_post_handshake');
  FuncLoadError := not assigned(SSL_verify_client_post_handshake);
  if FuncLoadError then
  begin
    SSL_verify_client_post_handshake :=  @ERROR_SSL_verify_client_post_handshake;
  end;

  SSL_CTX_get_ssl_method := LoadLibSSLFunction('SSL_CTX_get_ssl_method');
  FuncLoadError := not assigned(SSL_CTX_get_ssl_method);
  if FuncLoadError then
  begin
    SSL_CTX_get_ssl_method :=  @ERROR_SSL_CTX_get_ssl_method;
  end;

  SSL_get_ssl_method := LoadLibSSLFunction('SSL_get_ssl_method');
  FuncLoadError := not assigned(SSL_get_ssl_method);
  if FuncLoadError then
  begin
    SSL_get_ssl_method :=  @ERROR_SSL_get_ssl_method;
  end;

  SSL_set_ssl_method := LoadLibSSLFunction('SSL_set_ssl_method');
  FuncLoadError := not assigned(SSL_set_ssl_method);
  if FuncLoadError then
  begin
    SSL_set_ssl_method :=  @ERROR_SSL_set_ssl_method;
  end;

  SSL_alert_type_string_long := LoadLibSSLFunction('SSL_alert_type_string_long');
  FuncLoadError := not assigned(SSL_alert_type_string_long);
  if FuncLoadError then
  begin
    SSL_alert_type_string_long :=  @ERROR_SSL_alert_type_string_long;
  end;

  SSL_alert_type_string := LoadLibSSLFunction('SSL_alert_type_string');
  FuncLoadError := not assigned(SSL_alert_type_string);
  if FuncLoadError then
  begin
    SSL_alert_type_string :=  @ERROR_SSL_alert_type_string;
  end;

  SSL_alert_desc_string_long := LoadLibSSLFunction('SSL_alert_desc_string_long');
  FuncLoadError := not assigned(SSL_alert_desc_string_long);
  if FuncLoadError then
  begin
    SSL_alert_desc_string_long :=  @ERROR_SSL_alert_desc_string_long;
  end;

  SSL_alert_desc_string := LoadLibSSLFunction('SSL_alert_desc_string');
  FuncLoadError := not assigned(SSL_alert_desc_string);
  if FuncLoadError then
  begin
    SSL_alert_desc_string :=  @ERROR_SSL_alert_desc_string;
  end;

  SSL_CTX_set_client_CA_list := LoadLibSSLFunction('SSL_CTX_set_client_CA_list');
  FuncLoadError := not assigned(SSL_CTX_set_client_CA_list);
  if FuncLoadError then
  begin
    SSL_CTX_set_client_CA_list :=  @ERROR_SSL_CTX_set_client_CA_list;
  end;

  SSL_add_client_CA := LoadLibSSLFunction('SSL_add_client_CA');
  FuncLoadError := not assigned(SSL_add_client_CA);
  if FuncLoadError then
  begin
    SSL_add_client_CA :=  @ERROR_SSL_add_client_CA;
  end;

  SSL_CTX_add_client_CA := LoadLibSSLFunction('SSL_CTX_add_client_CA');
  FuncLoadError := not assigned(SSL_CTX_add_client_CA);
  if FuncLoadError then
  begin
    SSL_CTX_add_client_CA :=  @ERROR_SSL_CTX_add_client_CA;
  end;

  SSL_set_connect_state := LoadLibSSLFunction('SSL_set_connect_state');
  FuncLoadError := not assigned(SSL_set_connect_state);
  if FuncLoadError then
  begin
    SSL_set_connect_state :=  @ERROR_SSL_set_connect_state;
  end;

  SSL_set_accept_state := LoadLibSSLFunction('SSL_set_accept_state');
  FuncLoadError := not assigned(SSL_set_accept_state);
  if FuncLoadError then
  begin
    SSL_set_accept_state :=  @ERROR_SSL_set_accept_state;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_library_init := LoadLibSSLFunction('SSL_library_init');
  FuncLoadError := not assigned(SSL_library_init);
  if FuncLoadError then
  begin
    SSL_library_init := @COMPAT_SSL_library_init;
    if SSL_library_init_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_library_init');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CIPHER_description := LoadLibSSLFunction('SSL_CIPHER_description');
  FuncLoadError := not assigned(SSL_CIPHER_description);
  if FuncLoadError then
  begin
    SSL_CIPHER_description :=  @ERROR_SSL_CIPHER_description;
  end;

  SSL_dup := LoadLibSSLFunction('SSL_dup');
  FuncLoadError := not assigned(SSL_dup);
  if FuncLoadError then
  begin
    SSL_dup :=  @ERROR_SSL_dup;
  end;

  SSL_get_certificate := LoadLibSSLFunction('SSL_get_certificate');
  FuncLoadError := not assigned(SSL_get_certificate);
  if FuncLoadError then
  begin
    SSL_get_certificate :=  @ERROR_SSL_get_certificate;
  end;

  SSL_get_privatekey := LoadLibSSLFunction('SSL_get_privatekey');
  FuncLoadError := not assigned(SSL_get_privatekey);
  if FuncLoadError then
  begin
    SSL_get_privatekey :=  @ERROR_SSL_get_privatekey;
  end;

  SSL_CTX_get0_certificate := LoadLibSSLFunction('SSL_CTX_get0_certificate');
  FuncLoadError := not assigned(SSL_CTX_get0_certificate);
  if FuncLoadError then
  begin
    SSL_CTX_get0_certificate :=  @ERROR_SSL_CTX_get0_certificate;
  end;

  SSL_CTX_get0_privatekey := LoadLibSSLFunction('SSL_CTX_get0_privatekey');
  FuncLoadError := not assigned(SSL_CTX_get0_privatekey);
  if FuncLoadError then
  begin
    SSL_CTX_get0_privatekey :=  @ERROR_SSL_CTX_get0_privatekey;
  end;

  SSL_CTX_set_quiet_shutdown := LoadLibSSLFunction('SSL_CTX_set_quiet_shutdown');
  FuncLoadError := not assigned(SSL_CTX_set_quiet_shutdown);
  if FuncLoadError then
  begin
    SSL_CTX_set_quiet_shutdown :=  @ERROR_SSL_CTX_set_quiet_shutdown;
  end;

  SSL_CTX_get_quiet_shutdown := LoadLibSSLFunction('SSL_CTX_get_quiet_shutdown');
  FuncLoadError := not assigned(SSL_CTX_get_quiet_shutdown);
  if FuncLoadError then
  begin
    SSL_CTX_get_quiet_shutdown :=  @ERROR_SSL_CTX_get_quiet_shutdown;
  end;

  SSL_set_quiet_shutdown := LoadLibSSLFunction('SSL_set_quiet_shutdown');
  FuncLoadError := not assigned(SSL_set_quiet_shutdown);
  if FuncLoadError then
  begin
    SSL_set_quiet_shutdown :=  @ERROR_SSL_set_quiet_shutdown;
  end;

  SSL_get_quiet_shutdown := LoadLibSSLFunction('SSL_get_quiet_shutdown');
  FuncLoadError := not assigned(SSL_get_quiet_shutdown);
  if FuncLoadError then
  begin
    SSL_get_quiet_shutdown :=  @ERROR_SSL_get_quiet_shutdown;
  end;

  SSL_set_shutdown := LoadLibSSLFunction('SSL_set_shutdown');
  FuncLoadError := not assigned(SSL_set_shutdown);
  if FuncLoadError then
  begin
    SSL_set_shutdown :=  @ERROR_SSL_set_shutdown;
  end;

  SSL_get_shutdown := LoadLibSSLFunction('SSL_get_shutdown');
  FuncLoadError := not assigned(SSL_get_shutdown);
  if FuncLoadError then
  begin
    SSL_get_shutdown :=  @ERROR_SSL_get_shutdown;
  end;

  SSL_version := LoadLibSSLFunction('SSL_version');
  FuncLoadError := not assigned(SSL_version);
  if FuncLoadError then
  begin
    SSL_version :=  @ERROR_SSL_version;
  end;

  SSL_client_version := LoadLibSSLFunction('SSL_client_version');
  FuncLoadError := not assigned(SSL_client_version);
  if FuncLoadError then
  begin
    SSL_client_version :=  @ERROR_SSL_client_version;
  end;

  SSL_CTX_set_default_verify_paths := LoadLibSSLFunction('SSL_CTX_set_default_verify_paths');
  FuncLoadError := not assigned(SSL_CTX_set_default_verify_paths);
  if FuncLoadError then
  begin
    SSL_CTX_set_default_verify_paths :=  @ERROR_SSL_CTX_set_default_verify_paths;
  end;

  SSL_CTX_set_default_verify_dir := LoadLibSSLFunction('SSL_CTX_set_default_verify_dir');
  FuncLoadError := not assigned(SSL_CTX_set_default_verify_dir);
  if FuncLoadError then
  begin
    SSL_CTX_set_default_verify_dir :=  @ERROR_SSL_CTX_set_default_verify_dir;
  end;

  SSL_CTX_set_default_verify_file := LoadLibSSLFunction('SSL_CTX_set_default_verify_file');
  FuncLoadError := not assigned(SSL_CTX_set_default_verify_file);
  if FuncLoadError then
  begin
    SSL_CTX_set_default_verify_file :=  @ERROR_SSL_CTX_set_default_verify_file;
  end;

  SSL_CTX_load_verify_locations := LoadLibSSLFunction('SSL_CTX_load_verify_locations');
  FuncLoadError := not assigned(SSL_CTX_load_verify_locations);
  if FuncLoadError then
  begin
    SSL_CTX_load_verify_locations :=  @ERROR_SSL_CTX_load_verify_locations;
  end;

  SSL_get_session := LoadLibSSLFunction('SSL_get_session');
  FuncLoadError := not assigned(SSL_get_session);
  if FuncLoadError then
  begin
    SSL_get_session :=  @ERROR_SSL_get_session;
  end;

  SSL_get1_session := LoadLibSSLFunction('SSL_get1_session');
  FuncLoadError := not assigned(SSL_get1_session);
  if FuncLoadError then
  begin
    SSL_get1_session :=  @ERROR_SSL_get1_session;
  end;

  SSL_get_SSL_CTX := LoadLibSSLFunction('SSL_get_SSL_CTX');
  FuncLoadError := not assigned(SSL_get_SSL_CTX);
  if FuncLoadError then
  begin
    SSL_get_SSL_CTX :=  @ERROR_SSL_get_SSL_CTX;
  end;

  SSL_set_SSL_CTX := LoadLibSSLFunction('SSL_set_SSL_CTX');
  FuncLoadError := not assigned(SSL_set_SSL_CTX);
  if FuncLoadError then
  begin
    SSL_set_SSL_CTX :=  @ERROR_SSL_set_SSL_CTX;
  end;

  SSL_set_info_callback := LoadLibSSLFunction('SSL_set_info_callback');
  FuncLoadError := not assigned(SSL_set_info_callback);
  if FuncLoadError then
  begin
    SSL_set_info_callback :=  @ERROR_SSL_set_info_callback;
  end;

  SSL_get_info_callback := LoadLibSSLFunction('SSL_get_info_callback');
  FuncLoadError := not assigned(SSL_get_info_callback);
  if FuncLoadError then
  begin
    SSL_get_info_callback :=  @ERROR_SSL_get_info_callback;
  end;

  SSL_get_state := LoadLibSSLFunction('SSL_get_state');
  FuncLoadError := not assigned(SSL_get_state);
  if FuncLoadError then
  begin
    SSL_get_state :=  @ERROR_SSL_get_state;
  end;

  SSL_set_verify_result := LoadLibSSLFunction('SSL_set_verify_result');
  FuncLoadError := not assigned(SSL_set_verify_result);
  if FuncLoadError then
  begin
    SSL_set_verify_result :=  @ERROR_SSL_set_verify_result;
  end;

  SSL_get_verify_result := LoadLibSSLFunction('SSL_get_verify_result');
  FuncLoadError := not assigned(SSL_get_verify_result);
  if FuncLoadError then
  begin
    SSL_get_verify_result :=  @ERROR_SSL_get_verify_result;
  end;

  SSL_get_client_random := LoadLibSSLFunction('SSL_get_client_random');
  FuncLoadError := not assigned(SSL_get_client_random);
  if FuncLoadError then
  begin
    SSL_get_client_random :=  @ERROR_SSL_get_client_random;
  end;

  SSL_get_server_random := LoadLibSSLFunction('SSL_get_server_random');
  FuncLoadError := not assigned(SSL_get_server_random);
  if FuncLoadError then
  begin
    SSL_get_server_random :=  @ERROR_SSL_get_server_random;
  end;

  SSL_SESSION_get_master_key := LoadLibSSLFunction('SSL_SESSION_get_master_key');
  FuncLoadError := not assigned(SSL_SESSION_get_master_key);
  if FuncLoadError then
  begin
    SSL_SESSION_get_master_key :=  @ERROR_SSL_SESSION_get_master_key;
  end;

  SSL_SESSION_set1_master_key := LoadLibSSLFunction('SSL_SESSION_set1_master_key');
  FuncLoadError := not assigned(SSL_SESSION_set1_master_key);
  if FuncLoadError then
  begin
    SSL_SESSION_set1_master_key :=  @ERROR_SSL_SESSION_set1_master_key;
  end;

  SSL_SESSION_get_max_fragment_length := LoadLibSSLFunction('SSL_SESSION_get_max_fragment_length');
  FuncLoadError := not assigned(SSL_SESSION_get_max_fragment_length);
  if FuncLoadError then
  begin
    SSL_SESSION_get_max_fragment_length :=  @ERROR_SSL_SESSION_get_max_fragment_length;
  end;

  SSL_set_ex_data := LoadLibSSLFunction('SSL_set_ex_data');
  FuncLoadError := not assigned(SSL_set_ex_data);
  if FuncLoadError then
  begin
    SSL_set_ex_data :=  @ERROR_SSL_set_ex_data;
  end;

  SSL_get_ex_data := LoadLibSSLFunction('SSL_get_ex_data');
  FuncLoadError := not assigned(SSL_get_ex_data);
  if FuncLoadError then
  begin
    SSL_get_ex_data :=  @ERROR_SSL_get_ex_data;
  end;

  SSL_SESSION_set_ex_data := LoadLibSSLFunction('SSL_SESSION_set_ex_data');
  FuncLoadError := not assigned(SSL_SESSION_set_ex_data);
  if FuncLoadError then
  begin
    SSL_SESSION_set_ex_data :=  @ERROR_SSL_SESSION_set_ex_data;
  end;

  SSL_SESSION_get_ex_data := LoadLibSSLFunction('SSL_SESSION_get_ex_data');
  FuncLoadError := not assigned(SSL_SESSION_get_ex_data);
  if FuncLoadError then
  begin
    SSL_SESSION_get_ex_data :=  @ERROR_SSL_SESSION_get_ex_data;
  end;

  SSL_CTX_set_ex_data := LoadLibSSLFunction('SSL_CTX_set_ex_data');
  FuncLoadError := not assigned(SSL_CTX_set_ex_data);
  if FuncLoadError then
  begin
    SSL_CTX_set_ex_data :=  @ERROR_SSL_CTX_set_ex_data;
  end;

  SSL_CTX_get_ex_data := LoadLibSSLFunction('SSL_CTX_get_ex_data');
  FuncLoadError := not assigned(SSL_CTX_get_ex_data);
  if FuncLoadError then
  begin
    SSL_CTX_get_ex_data :=  @ERROR_SSL_CTX_get_ex_data;
  end;

  SSL_get_ex_data_X509_STORE_CTX_idx := LoadLibSSLFunction('SSL_get_ex_data_X509_STORE_CTX_idx');
  FuncLoadError := not assigned(SSL_get_ex_data_X509_STORE_CTX_idx);
  if FuncLoadError then
  begin
    SSL_get_ex_data_X509_STORE_CTX_idx :=  @ERROR_SSL_get_ex_data_X509_STORE_CTX_idx;
  end;

  SSL_CTX_set_default_read_buffer_len := LoadLibSSLFunction('SSL_CTX_set_default_read_buffer_len');
  FuncLoadError := not assigned(SSL_CTX_set_default_read_buffer_len);
  if FuncLoadError then
  begin
    SSL_CTX_set_default_read_buffer_len :=  @ERROR_SSL_CTX_set_default_read_buffer_len;
  end;

  SSL_set_default_read_buffer_len := LoadLibSSLFunction('SSL_set_default_read_buffer_len');
  FuncLoadError := not assigned(SSL_set_default_read_buffer_len);
  if FuncLoadError then
  begin
    SSL_set_default_read_buffer_len :=  @ERROR_SSL_set_default_read_buffer_len;
  end;

  SSL_CTX_set_tmp_dh_callback := LoadLibSSLFunction('SSL_CTX_set_tmp_dh_callback');
  FuncLoadError := not assigned(SSL_CTX_set_tmp_dh_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_tmp_dh_callback :=  @ERROR_SSL_CTX_set_tmp_dh_callback;
  end;

  SSL_set_tmp_dh_callback := LoadLibSSLFunction('SSL_set_tmp_dh_callback');
  FuncLoadError := not assigned(SSL_set_tmp_dh_callback);
  if FuncLoadError then
  begin
    SSL_set_tmp_dh_callback :=  @ERROR_SSL_set_tmp_dh_callback;
  end;

  SSL_CIPHER_find := LoadLibSSLFunction('SSL_CIPHER_find');
  FuncLoadError := not assigned(SSL_CIPHER_find);
  if FuncLoadError then
  begin
    SSL_CIPHER_find :=  @ERROR_SSL_CIPHER_find;
  end;

  SSL_CIPHER_get_cipher_nid := LoadLibSSLFunction('SSL_CIPHER_get_cipher_nid');
  FuncLoadError := not assigned(SSL_CIPHER_get_cipher_nid);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_cipher_nid :=  @ERROR_SSL_CIPHER_get_cipher_nid;
  end;

  SSL_CIPHER_get_digest_nid := LoadLibSSLFunction('SSL_CIPHER_get_digest_nid');
  FuncLoadError := not assigned(SSL_CIPHER_get_digest_nid);
  if FuncLoadError then
  begin
    SSL_CIPHER_get_digest_nid :=  @ERROR_SSL_CIPHER_get_digest_nid;
  end;

  SSL_set_session_ticket_ext := LoadLibSSLFunction('SSL_set_session_ticket_ext');
  FuncLoadError := not assigned(SSL_set_session_ticket_ext);
  if FuncLoadError then
  begin
    SSL_set_session_ticket_ext :=  @ERROR_SSL_set_session_ticket_ext;
  end;

  SSL_set_session_ticket_ext_cb := LoadLibSSLFunction('SSL_set_session_ticket_ext_cb');
  FuncLoadError := not assigned(SSL_set_session_ticket_ext_cb);
  if FuncLoadError then
  begin
    SSL_set_session_ticket_ext_cb :=  @ERROR_SSL_set_session_ticket_ext_cb;
  end;

  SSL_CTX_set_not_resumable_session_callback := LoadLibSSLFunction('SSL_CTX_set_not_resumable_session_callback');
  FuncLoadError := not assigned(SSL_CTX_set_not_resumable_session_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_not_resumable_session_callback :=  @ERROR_SSL_CTX_set_not_resumable_session_callback;
  end;

  SSL_set_not_resumable_session_callback := LoadLibSSLFunction('SSL_set_not_resumable_session_callback');
  FuncLoadError := not assigned(SSL_set_not_resumable_session_callback);
  if FuncLoadError then
  begin
    SSL_set_not_resumable_session_callback :=  @ERROR_SSL_set_not_resumable_session_callback;
  end;

  SSL_CTX_set_record_padding_callback := LoadLibSSLFunction('SSL_CTX_set_record_padding_callback');
  FuncLoadError := not assigned(SSL_CTX_set_record_padding_callback);
  if FuncLoadError then
  begin
    SSL_CTX_set_record_padding_callback :=  @ERROR_SSL_CTX_set_record_padding_callback;
  end;

  SSL_CTX_set_record_padding_callback_arg := LoadLibSSLFunction('SSL_CTX_set_record_padding_callback_arg');
  FuncLoadError := not assigned(SSL_CTX_set_record_padding_callback_arg);
  if FuncLoadError then
  begin
    SSL_CTX_set_record_padding_callback_arg :=  @ERROR_SSL_CTX_set_record_padding_callback_arg;
  end;

  SSL_CTX_get_record_padding_callback_arg := LoadLibSSLFunction('SSL_CTX_get_record_padding_callback_arg');
  FuncLoadError := not assigned(SSL_CTX_get_record_padding_callback_arg);
  if FuncLoadError then
  begin
    SSL_CTX_get_record_padding_callback_arg :=  @ERROR_SSL_CTX_get_record_padding_callback_arg;
  end;

  SSL_CTX_set_block_padding := LoadLibSSLFunction('SSL_CTX_set_block_padding');
  FuncLoadError := not assigned(SSL_CTX_set_block_padding);
  if FuncLoadError then
  begin
    SSL_CTX_set_block_padding :=  @ERROR_SSL_CTX_set_block_padding;
  end;

  SSL_set_record_padding_callback := LoadLibSSLFunction('SSL_set_record_padding_callback');
  FuncLoadError := not assigned(SSL_set_record_padding_callback);
  if FuncLoadError then
  begin
    SSL_set_record_padding_callback :=  @ERROR_SSL_set_record_padding_callback;
  end;

  SSL_set_record_padding_callback_arg := LoadLibSSLFunction('SSL_set_record_padding_callback_arg');
  FuncLoadError := not assigned(SSL_set_record_padding_callback_arg);
  if FuncLoadError then
  begin
    SSL_set_record_padding_callback_arg :=  @ERROR_SSL_set_record_padding_callback_arg;
  end;

  SSL_get_record_padding_callback_arg := LoadLibSSLFunction('SSL_get_record_padding_callback_arg');
  FuncLoadError := not assigned(SSL_get_record_padding_callback_arg);
  if FuncLoadError then
  begin
    SSL_get_record_padding_callback_arg :=  @ERROR_SSL_get_record_padding_callback_arg;
  end;

  SSL_set_block_padding := LoadLibSSLFunction('SSL_set_block_padding');
  FuncLoadError := not assigned(SSL_set_block_padding);
  if FuncLoadError then
  begin
    SSL_set_block_padding :=  @ERROR_SSL_set_block_padding;
  end;

  SSL_set_num_tickets := LoadLibSSLFunction('SSL_set_num_tickets');
  FuncLoadError := not assigned(SSL_set_num_tickets);
  if FuncLoadError then
  begin
    SSL_set_num_tickets :=  @ERROR_SSL_set_num_tickets;
  end;

  SSL_get_num_tickets := LoadLibSSLFunction('SSL_get_num_tickets');
  FuncLoadError := not assigned(SSL_get_num_tickets);
  if FuncLoadError then
  begin
    SSL_get_num_tickets :=  @ERROR_SSL_get_num_tickets;
  end;

  SSL_CTX_set_num_tickets := LoadLibSSLFunction('SSL_CTX_set_num_tickets');
  FuncLoadError := not assigned(SSL_CTX_set_num_tickets);
  if FuncLoadError then
  begin
    SSL_CTX_set_num_tickets :=  @ERROR_SSL_CTX_set_num_tickets;
  end;

  SSL_CTX_get_num_tickets := LoadLibSSLFunction('SSL_CTX_get_num_tickets');
  FuncLoadError := not assigned(SSL_CTX_get_num_tickets);
  if FuncLoadError then
  begin
    SSL_CTX_get_num_tickets :=  @ERROR_SSL_CTX_get_num_tickets;
  end;

  SSL_session_reused := LoadLibSSLFunction('SSL_session_reused');
  FuncLoadError := not assigned(SSL_session_reused);
  if FuncLoadError then
  begin
    SSL_session_reused :=  @ERROR_SSL_session_reused;
  end;

  SSL_is_server := LoadLibSSLFunction('SSL_is_server');
  FuncLoadError := not assigned(SSL_is_server);
  if FuncLoadError then
  begin
    SSL_is_server :=  @ERROR_SSL_is_server;
  end;

  SSL_CONF_CTX_new := LoadLibSSLFunction('SSL_CONF_CTX_new');
  FuncLoadError := not assigned(SSL_CONF_CTX_new);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_new :=  @ERROR_SSL_CONF_CTX_new;
  end;

  SSL_CONF_CTX_finish := LoadLibSSLFunction('SSL_CONF_CTX_finish');
  FuncLoadError := not assigned(SSL_CONF_CTX_finish);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_finish :=  @ERROR_SSL_CONF_CTX_finish;
  end;

  SSL_CONF_CTX_free := LoadLibSSLFunction('SSL_CONF_CTX_free');
  FuncLoadError := not assigned(SSL_CONF_CTX_free);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_free :=  @ERROR_SSL_CONF_CTX_free;
  end;

  SSL_CONF_CTX_set_flags := LoadLibSSLFunction('SSL_CONF_CTX_set_flags');
  FuncLoadError := not assigned(SSL_CONF_CTX_set_flags);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_set_flags :=  @ERROR_SSL_CONF_CTX_set_flags;
  end;

  SSL_CONF_CTX_clear_flags := LoadLibSSLFunction('SSL_CONF_CTX_clear_flags');
  FuncLoadError := not assigned(SSL_CONF_CTX_clear_flags);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_clear_flags :=  @ERROR_SSL_CONF_CTX_clear_flags;
  end;

  SSL_CONF_CTX_set1_prefix := LoadLibSSLFunction('SSL_CONF_CTX_set1_prefix');
  FuncLoadError := not assigned(SSL_CONF_CTX_set1_prefix);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_set1_prefix :=  @ERROR_SSL_CONF_CTX_set1_prefix;
  end;

  SSL_CONF_cmd := LoadLibSSLFunction('SSL_CONF_cmd');
  FuncLoadError := not assigned(SSL_CONF_cmd);
  if FuncLoadError then
  begin
    SSL_CONF_cmd :=  @ERROR_SSL_CONF_cmd;
  end;

  SSL_CONF_cmd_argv := LoadLibSSLFunction('SSL_CONF_cmd_argv');
  FuncLoadError := not assigned(SSL_CONF_cmd_argv);
  if FuncLoadError then
  begin
    SSL_CONF_cmd_argv :=  @ERROR_SSL_CONF_cmd_argv;
  end;

  SSL_CONF_cmd_value_type := LoadLibSSLFunction('SSL_CONF_cmd_value_type');
  FuncLoadError := not assigned(SSL_CONF_cmd_value_type);
  if FuncLoadError then
  begin
    SSL_CONF_cmd_value_type :=  @ERROR_SSL_CONF_cmd_value_type;
  end;

  SSL_CONF_CTX_set_ssl := LoadLibSSLFunction('SSL_CONF_CTX_set_ssl');
  FuncLoadError := not assigned(SSL_CONF_CTX_set_ssl);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_set_ssl :=  @ERROR_SSL_CONF_CTX_set_ssl;
  end;

  SSL_CONF_CTX_set_ssl_ctx := LoadLibSSLFunction('SSL_CONF_CTX_set_ssl_ctx');
  FuncLoadError := not assigned(SSL_CONF_CTX_set_ssl_ctx);
  if FuncLoadError then
  begin
    SSL_CONF_CTX_set_ssl_ctx :=  @ERROR_SSL_CONF_CTX_set_ssl_ctx;
  end;

  SSL_add_ssl_module := LoadLibSSLFunction('SSL_add_ssl_module');
  FuncLoadError := not assigned(SSL_add_ssl_module);
  if FuncLoadError then
  begin
    SSL_add_ssl_module :=  @ERROR_SSL_add_ssl_module;
  end;

  SSL_config := LoadLibSSLFunction('SSL_config');
  FuncLoadError := not assigned(SSL_config);
  if FuncLoadError then
  begin
    SSL_config :=  @ERROR_SSL_config;
  end;

  SSL_CTX_config := LoadLibSSLFunction('SSL_CTX_config');
  FuncLoadError := not assigned(SSL_CTX_config);
  if FuncLoadError then
  begin
    SSL_CTX_config :=  @ERROR_SSL_CTX_config;
  end;

  DTLSv1_listen := LoadLibSSLFunction('DTLSv1_listen');
  FuncLoadError := not assigned(DTLSv1_listen);
  if FuncLoadError then
  begin
    DTLSv1_listen :=  @ERROR_DTLSv1_listen;
  end;

  SSL_enable_ct := LoadLibSSLFunction('SSL_enable_ct');
  FuncLoadError := not assigned(SSL_enable_ct);
  if FuncLoadError then
  begin
    SSL_enable_ct :=  @ERROR_SSL_enable_ct;
  end;

  SSL_CTX_enable_ct := LoadLibSSLFunction('SSL_CTX_enable_ct');
  FuncLoadError := not assigned(SSL_CTX_enable_ct);
  if FuncLoadError then
  begin
    SSL_CTX_enable_ct :=  @ERROR_SSL_CTX_enable_ct;
  end;

  SSL_ct_is_enabled := LoadLibSSLFunction('SSL_ct_is_enabled');
  FuncLoadError := not assigned(SSL_ct_is_enabled);
  if FuncLoadError then
  begin
    SSL_ct_is_enabled :=  @ERROR_SSL_ct_is_enabled;
  end;

  SSL_CTX_ct_is_enabled := LoadLibSSLFunction('SSL_CTX_ct_is_enabled');
  FuncLoadError := not assigned(SSL_CTX_ct_is_enabled);
  if FuncLoadError then
  begin
    SSL_CTX_ct_is_enabled :=  @ERROR_SSL_CTX_ct_is_enabled;
  end;

  SSL_CTX_set_default_ctlog_list_file := LoadLibSSLFunction('SSL_CTX_set_default_ctlog_list_file');
  FuncLoadError := not assigned(SSL_CTX_set_default_ctlog_list_file);
  if FuncLoadError then
  begin
    SSL_CTX_set_default_ctlog_list_file :=  @ERROR_SSL_CTX_set_default_ctlog_list_file;
  end;

  SSL_CTX_set_ctlog_list_file := LoadLibSSLFunction('SSL_CTX_set_ctlog_list_file');
  FuncLoadError := not assigned(SSL_CTX_set_ctlog_list_file);
  if FuncLoadError then
  begin
    SSL_CTX_set_ctlog_list_file :=  @ERROR_SSL_CTX_set_ctlog_list_file;
  end;

  SSL_CTX_set0_ctlog_store := LoadLibSSLFunction('SSL_CTX_set0_ctlog_store');
  FuncLoadError := not assigned(SSL_CTX_set0_ctlog_store);
  if FuncLoadError then
  begin
    SSL_CTX_set0_ctlog_store :=  @ERROR_SSL_CTX_set0_ctlog_store;
  end;

  SSL_set_security_level := LoadLibSSLFunction('SSL_set_security_level');
  FuncLoadError := not assigned(SSL_set_security_level);
  if FuncLoadError then
  begin
    SSL_set_security_level :=  @ERROR_SSL_set_security_level;
  end;

  SSL_set_security_callback := LoadLibSSLFunction('SSL_set_security_callback');
  FuncLoadError := not assigned(SSL_set_security_callback);
  if FuncLoadError then
  begin
    SSL_set_security_callback :=  @ERROR_SSL_set_security_callback;
  end;

  SSL_get_security_callback := LoadLibSSLFunction('SSL_get_security_callback');
  FuncLoadError := not assigned(SSL_get_security_callback);
  if FuncLoadError then
  begin
    SSL_get_security_callback :=  @ERROR_SSL_get_security_callback;
  end;

  SSL_set0_security_ex_data := LoadLibSSLFunction('SSL_set0_security_ex_data');
  FuncLoadError := not assigned(SSL_set0_security_ex_data);
  if FuncLoadError then
  begin
    SSL_set0_security_ex_data :=  @ERROR_SSL_set0_security_ex_data;
  end;

  SSL_get0_security_ex_data := LoadLibSSLFunction('SSL_get0_security_ex_data');
  FuncLoadError := not assigned(SSL_get0_security_ex_data);
  if FuncLoadError then
  begin
    SSL_get0_security_ex_data :=  @ERROR_SSL_get0_security_ex_data;
  end;

  SSL_CTX_set_security_level := LoadLibSSLFunction('SSL_CTX_set_security_level');
  FuncLoadError := not assigned(SSL_CTX_set_security_level);
  if FuncLoadError then
  begin
    SSL_CTX_set_security_level :=  @ERROR_SSL_CTX_set_security_level;
  end;

  SSL_CTX_get_security_level := LoadLibSSLFunction('SSL_CTX_get_security_level');
  FuncLoadError := not assigned(SSL_CTX_get_security_level);
  if FuncLoadError then
  begin
    SSL_CTX_get_security_level :=  @ERROR_SSL_CTX_get_security_level;
  end;

  SSL_CTX_get0_security_ex_data := LoadLibSSLFunction('SSL_CTX_get0_security_ex_data');
  FuncLoadError := not assigned(SSL_CTX_get0_security_ex_data);
  if FuncLoadError then
  begin
    SSL_CTX_get0_security_ex_data :=  @ERROR_SSL_CTX_get0_security_ex_data;
  end;

  SSL_CTX_set0_security_ex_data := LoadLibSSLFunction('SSL_CTX_set0_security_ex_data');
  FuncLoadError := not assigned(SSL_CTX_set0_security_ex_data);
  if FuncLoadError then
  begin
    SSL_CTX_set0_security_ex_data :=  @ERROR_SSL_CTX_set0_security_ex_data;
  end;

  OPENSSL_init_ssl := LoadLibSSLFunction('OPENSSL_init_ssl');
  FuncLoadError := not assigned(OPENSSL_init_ssl);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_init_ssl := @COMPAT_OPENSSL_init_ssl;
{$ELSE}
    OPENSSL_init_ssl :=  @ERROR_OPENSSL_init_ssl;
{$ENDIF}
  end;

  SSL_free_buffers := LoadLibSSLFunction('SSL_free_buffers');
  FuncLoadError := not assigned(SSL_free_buffers);
  if FuncLoadError then
  begin
    SSL_free_buffers :=  @ERROR_SSL_free_buffers;
  end;

  SSL_alloc_buffers := LoadLibSSLFunction('SSL_alloc_buffers');
  FuncLoadError := not assigned(SSL_alloc_buffers);
  if FuncLoadError then
  begin
    SSL_alloc_buffers :=  @ERROR_SSL_alloc_buffers;
  end;

  SSL_CTX_set_session_ticket_cb := LoadLibSSLFunction('SSL_CTX_set_session_ticket_cb');
  FuncLoadError := not assigned(SSL_CTX_set_session_ticket_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_session_ticket_cb :=  @ERROR_SSL_CTX_set_session_ticket_cb;
  end;

  SSL_SESSION_set1_ticket_appdata := LoadLibSSLFunction('SSL_SESSION_set1_ticket_appdata');
  FuncLoadError := not assigned(SSL_SESSION_set1_ticket_appdata);
  if FuncLoadError then
  begin
    SSL_SESSION_set1_ticket_appdata :=  @ERROR_SSL_SESSION_set1_ticket_appdata;
  end;

  SSL_SESSION_get0_ticket_appdata := LoadLibSSLFunction('SSL_SESSION_get0_ticket_appdata');
  FuncLoadError := not assigned(SSL_SESSION_get0_ticket_appdata);
  if FuncLoadError then
  begin
    SSL_SESSION_get0_ticket_appdata :=  @ERROR_SSL_SESSION_get0_ticket_appdata;
  end;

  DTLS_set_timer_cb := LoadLibSSLFunction('DTLS_set_timer_cb');
  FuncLoadError := not assigned(DTLS_set_timer_cb);
  if FuncLoadError then
  begin
    DTLS_set_timer_cb :=  @ERROR_DTLS_set_timer_cb;
  end;

  SSL_CTX_set_allow_early_data_cb := LoadLibSSLFunction('SSL_CTX_set_allow_early_data_cb');
  FuncLoadError := not assigned(SSL_CTX_set_allow_early_data_cb);
  if FuncLoadError then
  begin
    SSL_CTX_set_allow_early_data_cb :=  @ERROR_SSL_CTX_set_allow_early_data_cb;
  end;

  SSL_set_allow_early_data_cb := LoadLibSSLFunction('SSL_set_allow_early_data_cb');
  FuncLoadError := not assigned(SSL_set_allow_early_data_cb);
  if FuncLoadError then
  begin
    SSL_set_allow_early_data_cb :=  @ERROR_SSL_set_allow_early_data_cb;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLv2_method := LoadLibSSLFunction('SSLv2_method');
  FuncLoadError := not assigned(SSLv2_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv2_server_method := LoadLibSSLFunction('SSLv2_server_method');
  FuncLoadError := not assigned(SSLv2_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv2_client_method := LoadLibSSLFunction('SSLv2_client_method');
  FuncLoadError := not assigned(SSLv2_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv3_method := LoadLibSSLFunction('SSLv3_method');
  FuncLoadError := not assigned(SSLv3_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv3_server_method := LoadLibSSLFunction('SSLv3_server_method');
  FuncLoadError := not assigned(SSLv3_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv3_client_method := LoadLibSSLFunction('SSLv3_client_method');
  FuncLoadError := not assigned(SSLv3_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv23_method := LoadLibSSLFunction('SSLv23_method');
  FuncLoadError := not assigned(SSLv23_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv23_server_method := LoadLibSSLFunction('SSLv23_server_method');
  FuncLoadError := not assigned(SSLv23_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv23_client_method := LoadLibSSLFunction('SSLv23_client_method');
  FuncLoadError := not assigned(SSLv23_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_method := LoadLibSSLFunction('TLSv1_method');
  FuncLoadError := not assigned(TLSv1_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_server_method := LoadLibSSLFunction('TLSv1_server_method');
  FuncLoadError := not assigned(TLSv1_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_client_method := LoadLibSSLFunction('TLSv1_client_method');
  FuncLoadError := not assigned(TLSv1_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_1_method := LoadLibSSLFunction('TLSv1_1_method');
  FuncLoadError := not assigned(TLSv1_1_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_1_server_method := LoadLibSSLFunction('TLSv1_1_server_method');
  FuncLoadError := not assigned(TLSv1_1_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_1_client_method := LoadLibSSLFunction('TLSv1_1_client_method');
  FuncLoadError := not assigned(TLSv1_1_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_2_method := LoadLibSSLFunction('TLSv1_2_method');
  FuncLoadError := not assigned(TLSv1_2_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_2_server_method := LoadLibSSLFunction('TLSv1_2_server_method');
  FuncLoadError := not assigned(TLSv1_2_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_2_client_method := LoadLibSSLFunction('TLSv1_2_client_method');
  FuncLoadError := not assigned(TLSv1_2_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_get0_peer_certificate := LoadLibSSLFunction('SSL_get0_peer_certificate');
  FuncLoadError := not assigned(SSL_get0_peer_certificate);
  if FuncLoadError then
  begin
    SSL_get0_peer_certificate :=  @ERROR_SSL_get0_peer_certificate;
    if LibVersion < SSL_get0_peer_certificate_introduced then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get0_peer_certificate');
  end;

  SSL_get1_peer_certificate := LoadLibSSLFunction('SSL_get1_peer_certificate');
  FuncLoadError := not assigned(SSL_get1_peer_certificate);
  if FuncLoadError then
  begin
    SSL_get1_peer_certificate :=  @ERROR_SSL_get1_peer_certificate;
    if LibVersion < SSL_get1_peer_certificate_introduced then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSL_get1_peer_certificate');
  end;

end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_CTX_set_mode := nil;
  SSL_CTX_clear_mode := nil;
  SSL_CTX_sess_set_cache_size := nil;
  SSL_CTX_sess_get_cache_size := nil;
  SSL_CTX_set_session_cache_mode := nil;
  SSL_CTX_get_session_cache_mode := nil;
  SSL_clear_num_renegotiations := nil;
  SSL_total_renegotiations := nil;
  SSL_CTX_set_tmp_dh := nil;
  SSL_CTX_set_tmp_ecdh := nil;
  SSL_CTX_set_dh_auto := nil;
  SSL_set_dh_auto := nil;
  SSL_set_tmp_dh := nil;
  SSL_set_tmp_ecdh := nil;
  SSL_CTX_add_extra_chain_cert := nil;
  SSL_CTX_get_extra_chain_certs := nil;
  SSL_CTX_get_extra_chain_certs_only := nil;
  SSL_CTX_clear_extra_chain_certs := nil;
  SSL_CTX_set0_chain := nil;
  SSL_CTX_set1_chain := nil;
  SSL_CTX_add0_chain_cert := nil;
  SSL_CTX_add1_chain_cert := nil;
  SSL_CTX_get0_chain_certs := nil;
  SSL_CTX_clear_chain_certs := nil;
  SSL_CTX_build_cert_chain := nil;
  SSL_CTX_select_current_cert := nil;
  SSL_CTX_set_current_cert := nil;
  SSL_CTX_set0_verify_cert_store := nil;
  SSL_CTX_set1_verify_cert_store := nil;
  SSL_CTX_set0_chain_cert_store := nil;
  SSL_CTX_set1_chain_cert_store := nil;
  SSL_set0_chain := nil;
  SSL_set1_chain := nil;
  SSL_add0_chain_cert := nil;
  SSL_add1_chain_cert := nil;
  SSL_get0_chain_certs := nil;
  SSL_clear_chain_certs := nil;
  SSL_build_cert_chain := nil;
  SSL_select_current_cert := nil;
  SSL_set_current_cert := nil;
  SSL_set0_verify_cert_store := nil;
  SSL_set1_verify_cert_store := nil;
  SSL_set0_chain_cert_store := nil;
  SSL_set1_chain_cert_store := nil;
  SSL_get1_groups := nil;
  SSL_CTX_set1_groups := nil;
  SSL_CTX_set1_groups_list := nil;
  SSL_set1_groups := nil;
  SSL_set1_groups_list := nil;
  SSL_get_shared_group := nil;
  SSL_CTX_set1_sigalgs := nil;
  SSL_CTX_set1_sigalgs_list := nil;
  SSL_set1_sigalgs := nil;
  SSL_set1_sigalgs_list := nil;
  SSL_CTX_set1_client_sigalgs := nil;
  SSL_CTX_set1_client_sigalgs_list := nil;
  SSL_set1_client_sigalgs := nil;
  SSL_set1_client_sigalgs_list := nil;
  SSL_get0_certificate_types := nil;
  SSL_CTX_set1_client_certificate_types := nil;
  SSL_set1_client_certificate_types := nil;
  SSL_get_signature_nid := nil;
  SSL_get_peer_signature_nid := nil;
  SSL_get_peer_tmp_key := nil;
  SSL_get_tmp_key := nil;
  SSL_get0_raw_cipherlist := nil;
  SSL_get0_ec_point_formats := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CTX_get_options := nil;
  SSL_get_options := nil;
  SSL_CTX_clear_options := nil;
  SSL_clear_options := nil;
  SSL_CTX_set_options := nil;
  SSL_set_options := nil;
  SSL_CTX_sess_set_new_cb := nil;
  SSL_CTX_sess_get_new_cb := nil;
  SSL_CTX_sess_set_remove_cb := nil;
  SSL_CTX_sess_get_remove_cb := nil;
  SSL_CTX_set_info_callback := nil;
  SSL_CTX_get_info_callback := nil;
  SSL_CTX_set_client_cert_cb := nil;
  SSL_CTX_get_client_cert_cb := nil;
  SSL_CTX_set_client_cert_engine := nil;
  SSL_CTX_set_cookie_generate_cb := nil;
  SSL_CTX_set_cookie_verify_cb := nil;
  SSL_CTX_set_stateless_cookie_generate_cb := nil;
  SSL_CTX_set_stateless_cookie_verify_cb := nil;
  SSL_CTX_set_alpn_select_cb := nil;
  SSL_get0_alpn_selected := nil;
  SSL_CTX_set_psk_client_callback := nil;
  SSL_set_psk_client_callback := nil;
  SSL_CTX_set_psk_server_callback := nil;
  SSL_set_psk_server_callback := nil;
  SSL_set_psk_find_session_callback := nil;
  SSL_CTX_set_psk_find_session_callback := nil;
  SSL_set_psk_use_session_callback := nil;
  SSL_CTX_set_psk_use_session_callback := nil;
  SSL_CTX_set_keylog_callback := nil;
  SSL_CTX_get_keylog_callback := nil;
  SSL_CTX_set_max_early_data := nil;
  SSL_CTX_get_max_early_data := nil;
  SSL_set_max_early_data := nil;
  SSL_get_max_early_data := nil;
  SSL_CTX_set_recv_max_early_data := nil;
  SSL_CTX_get_recv_max_early_data := nil;
  SSL_set_recv_max_early_data := nil;
  SSL_get_recv_max_early_data := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_get_app_data := nil;
  SSL_set_app_data := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_in_init := nil;
  SSL_in_before := nil;
  SSL_is_init_finished := nil;
  SSL_get_finished := nil;
  SSL_get_peer_finished := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLeay_add_ssl_algorithms := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  BIO_f_ssl := nil;
  BIO_new_ssl := nil;
  BIO_new_ssl_connect := nil;
  BIO_new_buffer_ssl_connect := nil;
  BIO_ssl_copy_session_id := nil;
  SSL_CTX_set_cipher_list := nil;
  SSL_CTX_new := nil;
  SSL_CTX_set_timeout := nil;
  SSL_CTX_get_timeout := nil;
  SSL_CTX_get_cert_store := nil;
  SSL_want := nil;
  SSL_clear := nil;
  BIO_ssl_shutdown := nil;
  SSL_CTX_up_ref := nil;
  SSL_CTX_free := nil;
  SSL_CTX_set_cert_store := nil;
  SSL_CTX_set1_cert_store := nil;
  SSL_CTX_flush_sessions := nil;
  SSL_get_current_cipher := nil;
  SSL_get_pending_cipher := nil;
  SSL_CIPHER_get_bits := nil;
  SSL_CIPHER_get_version := nil;
  SSL_CIPHER_get_name := nil;
  SSL_CIPHER_standard_name := nil;
  OPENSSL_cipher_name := nil;
  SSL_CIPHER_get_id := nil;
  SSL_CIPHER_get_protocol_id := nil;
  SSL_CIPHER_get_kx_nid := nil;
  SSL_CIPHER_get_auth_nid := nil;
  SSL_CIPHER_get_handshake_digest := nil;
  SSL_CIPHER_is_aead := nil;
  SSL_get_fd := nil;
  SSL_get_rfd := nil;
  SSL_get_wfd := nil;
  SSL_get_cipher_list := nil;
  SSL_get_shared_ciphers := nil;
  SSL_get_read_ahead := nil;
  SSL_pending := nil;
  SSL_has_pending := nil;
  SSL_set_fd := nil;
  SSL_set_rfd := nil;
  SSL_set_wfd := nil;
  SSL_set0_rbio := nil;
  SSL_set0_wbio := nil;
  SSL_set_bio := nil;
  SSL_get_rbio := nil;
  SSL_get_wbio := nil;
  SSL_set_cipher_list := nil;
  SSL_CTX_set_ciphersuites := nil;
  SSL_set_ciphersuites := nil;
  SSL_get_verify_mode := nil;
  SSL_get_verify_depth := nil;
  SSL_get_verify_callback := nil;
  SSL_set_read_ahead := nil;
  SSL_set_verify := nil;
  SSL_set_verify_depth := nil;
  SSL_use_RSAPrivateKey := nil;
  SSL_use_RSAPrivateKey_ASN1 := nil;
  SSL_use_PrivateKey := nil;
  SSL_use_PrivateKey_ASN1 := nil;
  SSL_use_certificate := nil;
  SSL_use_certificate_ASN1 := nil;
  SSL_CTX_use_serverinfo := nil;
  SSL_CTX_use_serverinfo_ex := nil;
  SSL_CTX_use_serverinfo_file := nil;
  SSL_use_RSAPrivateKey_file := nil;
  SSL_use_PrivateKey_file := nil;
  SSL_use_certificate_file := nil;
  SSL_CTX_use_RSAPrivateKey_file := nil;
  SSL_CTX_use_PrivateKey_file := nil;
  SSL_CTX_use_certificate_file := nil;
  SSL_CTX_use_certificate_chain_file := nil;
  SSL_use_certificate_chain_file := nil;
  SSL_load_client_CA_file := nil;
  SSL_add_file_cert_subjects_to_stack := nil;
  SSL_add_dir_cert_subjects_to_stack := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_load_error_strings := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_state_string := nil;
  SSL_rstate_string := nil;
  SSL_state_string_long := nil;
  SSL_rstate_string_long := nil;
  SSL_SESSION_get_time := nil;
  SSL_SESSION_set_time := nil;
  SSL_SESSION_get_timeout := nil;
  SSL_SESSION_set_timeout := nil;
  SSL_SESSION_get_protocol_version := nil;
  SSL_SESSION_set_protocol_version := nil;
  SSL_SESSION_get0_hostname := nil;
  SSL_SESSION_set1_hostname := nil;
  SSL_SESSION_get0_alpn_selected := nil;
  SSL_SESSION_set1_alpn_selected := nil;
  SSL_SESSION_get0_cipher := nil;
  SSL_SESSION_set_cipher := nil;
  SSL_SESSION_has_ticket := nil;
  SSL_SESSION_get_ticket_lifetime_hint := nil;
  SSL_SESSION_get0_ticket := nil;
  SSL_SESSION_get_max_early_data := nil;
  SSL_SESSION_set_max_early_data := nil;
  SSL_copy_session_id := nil;
  SSL_SESSION_get0_peer := nil;
  SSL_SESSION_set1_id_context := nil;
  SSL_SESSION_set1_id := nil;
  SSL_SESSION_is_resumable := nil;
  SSL_SESSION_new := nil;
  SSL_SESSION_dup := nil;
  SSL_SESSION_get_id := nil;
  SSL_SESSION_get0_id_context := nil;
  SSL_SESSION_get_compress_id := nil;
  SSL_SESSION_print := nil;
  SSL_SESSION_print_keylog := nil;
  SSL_SESSION_up_ref := nil;
  SSL_SESSION_free := nil;
  SSL_set_session := nil;
  SSL_CTX_add_session := nil;
  SSL_CTX_remove_session := nil;
  SSL_CTX_set_generate_session_id := nil;
  SSL_set_generate_session_id := nil;
  SSL_has_matching_session_id := nil;
  d2i_SSL_SESSION := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_get_peer_certificate := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CTX_get_verify_mode := nil;
  SSL_CTX_get_verify_depth := nil;
  SSL_CTX_get_verify_callback := nil;
  SSL_CTX_set_verify := nil;
  SSL_CTX_set_verify_depth := nil;
  SSL_CTX_set_cert_verify_callback := nil;
  SSL_CTX_set_cert_cb := nil;
  SSL_CTX_use_RSAPrivateKey := nil;
  SSL_CTX_use_RSAPrivateKey_ASN1 := nil;
  SSL_CTX_use_PrivateKey := nil;
  SSL_CTX_use_PrivateKey_ASN1 := nil;
  SSL_CTX_use_certificate := nil;
  SSL_CTX_use_certificate_ASN1 := nil;
  SSL_CTX_set_default_passwd_cb := nil;
  SSL_CTX_set_default_passwd_cb_userdata := nil;
  SSL_CTX_get_default_passwd_cb := nil;
  SSL_CTX_get_default_passwd_cb_userdata := nil;
  SSL_set_default_passwd_cb := nil;
  SSL_set_default_passwd_cb_userdata := nil;
  SSL_get_default_passwd_cb := nil;
  SSL_get_default_passwd_cb_userdata := nil;
  SSL_CTX_check_private_key := nil;
  SSL_check_private_key := nil;
  SSL_CTX_set_session_id_context := nil;
  SSL_new := nil;
  SSL_up_ref := nil;
  SSL_is_dtls := nil;
  SSL_set_session_id_context := nil;
  SSL_CTX_set_purpose := nil;
  SSL_set_purpose := nil;
  SSL_CTX_set_trust := nil;
  SSL_set_trust := nil;
  SSL_set1_host := nil;
  SSL_add1_host := nil;
  SSL_get0_peername := nil;
  SSL_set_hostflags := nil;
  SSL_CTX_dane_enable := nil;
  SSL_CTX_dane_mtype_set := nil;
  SSL_dane_enable := nil;
  SSL_dane_tlsa_add := nil;
  SSL_get0_dane_authority := nil;
  SSL_get0_dane_tlsa := nil;
  SSL_get0_dane := nil;
  SSL_CTX_dane_set_flags := nil;
  SSL_CTX_dane_clear_flags := nil;
  SSL_dane_set_flags := nil;
  SSL_dane_clear_flags := nil;
  SSL_CTX_set1_param := nil;
  SSL_set1_param := nil;
  SSL_CTX_get0_param := nil;
  SSL_get0_param := nil;
  SSL_CTX_set_srp_username := nil;
  SSL_CTX_set_srp_password := nil;
  SSL_CTX_set_srp_strength := nil;
  SSL_CTX_set_srp_client_pwd_callback := nil;
  SSL_CTX_set_srp_verify_param_callback := nil;
  SSL_CTX_set_srp_username_callback := nil;
  SSL_CTX_set_srp_cb_arg := nil;
  SSL_set_srp_server_param := nil;
  SSL_set_srp_server_param_pw := nil;
  SSL_CTX_set_client_hello_cb := nil;
  SSL_client_hello_isv2 := nil;
  SSL_client_hello_get0_legacy_version := nil;
  SSL_client_hello_get0_random := nil;
  SSL_client_hello_get0_session_id := nil;
  SSL_client_hello_get0_ciphers := nil;
  SSL_client_hello_get0_compression_methods := nil;
  SSL_client_hello_get1_extensions_present := nil;
  SSL_client_hello_get0_ext := nil;
  SSL_certs_clear := nil;
  SSL_free := nil;
  SSL_waiting_for_async := nil;
  SSL_get_all_async_fds := nil;
  SSL_get_changed_async_fds := nil;
  SSL_accept := nil;
  SSL_stateless := nil;
  SSL_connect := nil;
  SSL_read := nil;
  SSL_read_ex := nil;
  SSL_read_early_data := nil;
  SSL_peek := nil;
  SSL_peek_ex := nil;
  SSL_write := nil;
  SSL_write_ex := nil;
  SSL_write_early_data := nil;
  SSL_callback_ctrl := nil;
  SSL_ctrl := nil;
  SSL_CTX_ctrl := nil;
  SSL_CTX_callback_ctrl := nil;
  SSL_get_early_data_status := nil;
  SSL_get_error := nil;
  SSL_get_version := nil;
  SSL_CTX_set_ssl_version := nil;
  TLS_method := nil;
  TLS_server_method := nil;
  TLS_client_method := nil;
  SSL_do_handshake := nil;
  SSL_key_update := nil;
  SSL_get_key_update_type := nil;
  SSL_renegotiate := nil;
  SSL_renegotiate_abbreviated := nil;
  SSL_new_session_ticket := nil;
  SSL_shutdown := nil;
  SSL_CTX_set_post_handshake_auth := nil;
  SSL_set_post_handshake_auth := nil;
  SSL_renegotiate_pending := nil;
  SSL_verify_client_post_handshake := nil;
  SSL_CTX_get_ssl_method := nil;
  SSL_get_ssl_method := nil;
  SSL_set_ssl_method := nil;
  SSL_alert_type_string_long := nil;
  SSL_alert_type_string := nil;
  SSL_alert_desc_string_long := nil;
  SSL_alert_desc_string := nil;
  SSL_CTX_set_client_CA_list := nil;
  SSL_add_client_CA := nil;
  SSL_CTX_add_client_CA := nil;
  SSL_set_connect_state := nil;
  SSL_set_accept_state := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_library_init := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CIPHER_description := nil;
  SSL_dup := nil;
  SSL_get_certificate := nil;
  SSL_get_privatekey := nil;
  SSL_CTX_get0_certificate := nil;
  SSL_CTX_get0_privatekey := nil;
  SSL_CTX_set_quiet_shutdown := nil;
  SSL_CTX_get_quiet_shutdown := nil;
  SSL_set_quiet_shutdown := nil;
  SSL_get_quiet_shutdown := nil;
  SSL_set_shutdown := nil;
  SSL_get_shutdown := nil;
  SSL_version := nil;
  SSL_client_version := nil;
  SSL_CTX_set_default_verify_paths := nil;
  SSL_CTX_set_default_verify_dir := nil;
  SSL_CTX_set_default_verify_file := nil;
  SSL_CTX_load_verify_locations := nil;
  SSL_get_session := nil;
  SSL_get1_session := nil;
  SSL_get_SSL_CTX := nil;
  SSL_set_SSL_CTX := nil;
  SSL_set_info_callback := nil;
  SSL_get_info_callback := nil;
  SSL_get_state := nil;
  SSL_set_verify_result := nil;
  SSL_get_verify_result := nil;
  SSL_get_client_random := nil;
  SSL_get_server_random := nil;
  SSL_SESSION_get_master_key := nil;
  SSL_SESSION_set1_master_key := nil;
  SSL_SESSION_get_max_fragment_length := nil;
  SSL_set_ex_data := nil;
  SSL_get_ex_data := nil;
  SSL_SESSION_set_ex_data := nil;
  SSL_SESSION_get_ex_data := nil;
  SSL_CTX_set_ex_data := nil;
  SSL_CTX_get_ex_data := nil;
  SSL_get_ex_data_X509_STORE_CTX_idx := nil;
  SSL_CTX_set_default_read_buffer_len := nil;
  SSL_set_default_read_buffer_len := nil;
  SSL_CTX_set_tmp_dh_callback := nil;
  SSL_set_tmp_dh_callback := nil;
  SSL_CIPHER_find := nil;
  SSL_CIPHER_get_cipher_nid := nil;
  SSL_CIPHER_get_digest_nid := nil;
  SSL_set_session_ticket_ext := nil;
  SSL_set_session_ticket_ext_cb := nil;
  SSL_CTX_set_not_resumable_session_callback := nil;
  SSL_set_not_resumable_session_callback := nil;
  SSL_CTX_set_record_padding_callback := nil;
  SSL_CTX_set_record_padding_callback_arg := nil;
  SSL_CTX_get_record_padding_callback_arg := nil;
  SSL_CTX_set_block_padding := nil;
  SSL_set_record_padding_callback := nil;
  SSL_set_record_padding_callback_arg := nil;
  SSL_get_record_padding_callback_arg := nil;
  SSL_set_block_padding := nil;
  SSL_set_num_tickets := nil;
  SSL_get_num_tickets := nil;
  SSL_CTX_set_num_tickets := nil;
  SSL_CTX_get_num_tickets := nil;
  SSL_session_reused := nil;
  SSL_is_server := nil;
  SSL_CONF_CTX_new := nil;
  SSL_CONF_CTX_finish := nil;
  SSL_CONF_CTX_free := nil;
  SSL_CONF_CTX_set_flags := nil;
  SSL_CONF_CTX_clear_flags := nil;
  SSL_CONF_CTX_set1_prefix := nil;
  SSL_CONF_cmd := nil;
  SSL_CONF_cmd_argv := nil;
  SSL_CONF_cmd_value_type := nil;
  SSL_CONF_CTX_set_ssl := nil;
  SSL_CONF_CTX_set_ssl_ctx := nil;
  SSL_add_ssl_module := nil;
  SSL_config := nil;
  SSL_CTX_config := nil;
  DTLSv1_listen := nil;
  SSL_enable_ct := nil;
  SSL_CTX_enable_ct := nil;
  SSL_ct_is_enabled := nil;
  SSL_CTX_ct_is_enabled := nil;
  SSL_CTX_set_default_ctlog_list_file := nil;
  SSL_CTX_set_ctlog_list_file := nil;
  SSL_CTX_set0_ctlog_store := nil;
  SSL_set_security_level := nil;
  SSL_set_security_callback := nil;
  SSL_get_security_callback := nil;
  SSL_set0_security_ex_data := nil;
  SSL_get0_security_ex_data := nil;
  SSL_CTX_set_security_level := nil;
  SSL_CTX_get_security_level := nil;
  SSL_CTX_get0_security_ex_data := nil;
  SSL_CTX_set0_security_ex_data := nil;
  OPENSSL_init_ssl := nil;
  SSL_free_buffers := nil;
  SSL_alloc_buffers := nil;
  SSL_CTX_set_session_ticket_cb := nil;
  SSL_SESSION_set1_ticket_appdata := nil;
  SSL_SESSION_get0_ticket_appdata := nil;
  DTLS_set_timer_cb := nil;
  SSL_CTX_set_allow_early_data_cb := nil;
  SSL_set_allow_early_data_cb := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLv2_method := nil;
  SSLv2_server_method := nil;
  SSLv2_client_method := nil;
  SSLv3_method := nil;
  SSLv3_server_method := nil;
  SSLv3_client_method := nil;
  SSLv23_method := nil;
  SSLv23_server_method := nil;
  SSLv23_client_method := nil;
  TLSv1_method := nil;
  TLSv1_server_method := nil;
  TLSv1_client_method := nil;
  TLSv1_1_method := nil;
  TLSv1_1_server_method := nil;
  TLSv1_1_client_method := nil;
  TLSv1_2_method := nil;
  TLSv1_2_server_method := nil;
  TLSv1_2_client_method := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_get0_peer_certificate := nil;
  SSL_get1_peer_certificate := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
