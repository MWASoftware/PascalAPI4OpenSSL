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

unit openssl_core_names;

{
  Generated from OpenSSL 3.0.20 Header File core_names.h - Tue 19 May 14:15:43 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_core_names.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CORE_NAMES_H}
  {$define OPENSSL_CORE_NAMES_H}

const
  { Well known parameter names that core passes to providers }
  OSSL_PROV_PARAM_CORE_VERSION = 'openssl-version';
  OSSL_PROV_PARAM_CORE_PROV_NAME = 'provider-name';
  OSSL_PROV_PARAM_CORE_MODULE_FILENAME = 'module-filename';
  { Well known parameter names that Providers can define }
  OSSL_PROV_PARAM_NAME = 'name';
  OSSL_PROV_PARAM_VERSION = 'version';
  OSSL_PROV_PARAM_BUILDINFO = 'buildinfo';
  OSSL_PROV_PARAM_STATUS = 'status';
  OSSL_PROV_PARAM_SECURITY_CHECKS = 'security-checks';
  { Self test callback parameters }
  OSSL_PROV_PARAM_SELF_TEST_PHASE = 'st-phase';
  OSSL_PROV_PARAM_SELF_TEST_TYPE = 'st-type';
  OSSL_PROV_PARAM_SELF_TEST_DESC = 'st-desc';
  {-
  * Provider-native object abstractions
  *
  * These are used when a provider wants to pass object data or an object
  * reference back to libcrypto.  This is only useful for provider functions
  * that take a callback to which an OSSL_PARAM array with these parameters
  * can be passed.
  *
  * This set of parameter names is explained in detail in provider-object(7)
  * (doc/man7/provider-object.pod)
  }
  OSSL_OBJECT_PARAM_TYPE = 'type';
  OSSL_OBJECT_PARAM_DATA_TYPE = 'data-type';
  OSSL_OBJECT_PARAM_DATA_STRUCTURE = 'data-structure';
  OSSL_OBJECT_PARAM_REFERENCE = 'reference';
  OSSL_OBJECT_PARAM_DATA = 'data';
  OSSL_OBJECT_PARAM_DESC = 'desc';
  
  {* Algorithm parameters
  * If "engine" or "properties" are specified, they should always be paired
  * with the algorithm type.
  * Note these are common names that are shared by many types (such as kdf, mac,
  * and pkey) e.g: see OSSL_MAC_PARAM_DIGEST below.
  }
  OSSL_ALG_PARAM_DIGEST = 'digest';
  OSSL_ALG_PARAM_CIPHER = 'cipher';
  OSSL_ALG_PARAM_ENGINE = 'engine';
  OSSL_ALG_PARAM_MAC = 'mac';
  OSSL_ALG_PARAM_PROPERTIES = 'properties';
  { cipher parameters }
  OSSL_CIPHER_PARAM_PADDING = 'padding';
  OSSL_CIPHER_PARAM_USE_BITS = 'use-bits';
  OSSL_CIPHER_PARAM_TLS_VERSION = 'tls-version';
  OSSL_CIPHER_PARAM_TLS_MAC = 'tls-mac';
  OSSL_CIPHER_PARAM_TLS_MAC_SIZE = 'tls-mac-size';
  OSSL_CIPHER_PARAM_MODE = 'mode';
  OSSL_CIPHER_PARAM_BLOCK_SIZE = 'blocksize';
  OSSL_CIPHER_PARAM_AEAD = 'aead';
  OSSL_CIPHER_PARAM_CUSTOM_IV = 'custom-iv';
  OSSL_CIPHER_PARAM_CTS = 'cts';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK = 'tls-multi';
  OSSL_CIPHER_PARAM_HAS_RAND_KEY = 'has-randkey';
  OSSL_CIPHER_PARAM_KEYLEN = 'keylen';
  OSSL_CIPHER_PARAM_IVLEN = 'ivlen';
  OSSL_CIPHER_PARAM_IV = 'iv';
  OSSL_CIPHER_PARAM_UPDATED_IV = 'updated-iv';
  OSSL_CIPHER_PARAM_NUM = 'num';
  OSSL_CIPHER_PARAM_ROUNDS = 'rounds';
  OSSL_CIPHER_PARAM_AEAD_TAG = 'tag';
  OSSL_CIPHER_PARAM_AEAD_TLS1_AAD = 'tlsaad';
  OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD = 'tlsaadpad';
  OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED = 'tlsivfixed';
  OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN = 'tlsivgen';
  OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV = 'tlsivinv';
  OSSL_CIPHER_PARAM_AEAD_IVLEN = OSSL_CIPHER_PARAM_IVLEN;
  OSSL_CIPHER_PARAM_AEAD_TAGLEN = 'taglen';
  OSSL_CIPHER_PARAM_AEAD_MAC_KEY = 'mackey';
  OSSL_CIPHER_PARAM_RANDOM_KEY = 'randkey';
  OSSL_CIPHER_PARAM_RC2_KEYBITS = 'keybits';
  OSSL_CIPHER_PARAM_SPEED = 'speed';
  OSSL_CIPHER_PARAM_CTS_MODE = 'cts_mode';
  { For passing the AlgorithmIdentifier parameter in DER form }
  OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS = 'alg_id_param';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT = 'tls1multi_maxsndfrag';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE = 'tls1multi_maxbufsz';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE = 'tls1multi_interleave';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD = 'tls1multi_aad';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN = 'tls1multi_aadpacklen';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC = 'tls1multi_enc';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN = 'tls1multi_encin';
  OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN = 'tls1multi_enclen';
  { OSSL_CIPHER_PARAM_CTS_MODE Values }
  OSSL_CIPHER_CTS_MODE_CS1 = 'CS1';
  OSSL_CIPHER_CTS_MODE_CS2 = 'CS2';
  OSSL_CIPHER_CTS_MODE_CS3 = 'CS3';
  { digest parameters }
  OSSL_DIGEST_PARAM_XOFLEN = 'xoflen';
  OSSL_DIGEST_PARAM_SSL3_MS = 'ssl3-ms';
  OSSL_DIGEST_PARAM_PAD_TYPE = 'pad-type';
  OSSL_DIGEST_PARAM_MICALG = 'micalg';
  OSSL_DIGEST_PARAM_BLOCK_SIZE = 'blocksize';
  OSSL_DIGEST_PARAM_SIZE = 'size';
  OSSL_DIGEST_PARAM_XOF = 'xof';
  OSSL_DIGEST_PARAM_ALGID_ABSENT = 'algid-absent';
  { Known DIGEST names (not a complete list) }
  OSSL_DIGEST_NAME_MD5 = 'MD5';
  OSSL_DIGEST_NAME_MD5_SHA1 = 'MD5-SHA1';
  OSSL_DIGEST_NAME_SHA1 = 'SHA1';
  OSSL_DIGEST_NAME_SHA2_224 = 'SHA2-224';
  OSSL_DIGEST_NAME_SHA2_256 = 'SHA2-256';
  OSSL_DIGEST_NAME_SHA2_384 = 'SHA2-384';
  OSSL_DIGEST_NAME_SHA2_512 = 'SHA2-512';
  OSSL_DIGEST_NAME_SHA2_512_224 = 'SHA2-512/224';
  OSSL_DIGEST_NAME_SHA2_512_256 = 'SHA2-512/256';
  OSSL_DIGEST_NAME_MD2 = 'MD2';
  OSSL_DIGEST_NAME_MD4 = 'MD4';
  OSSL_DIGEST_NAME_MDC2 = 'MDC2';
  OSSL_DIGEST_NAME_RIPEMD160 = 'RIPEMD160';
  OSSL_DIGEST_NAME_SHA3_224 = 'SHA3-224';
  OSSL_DIGEST_NAME_SHA3_256 = 'SHA3-256';
  OSSL_DIGEST_NAME_SHA3_384 = 'SHA3-384';
  OSSL_DIGEST_NAME_SHA3_512 = 'SHA3-512';
  OSSL_DIGEST_NAME_KECCAK_KMAC128 = 'KECCAK-KMAC-128';
  OSSL_DIGEST_NAME_KECCAK_KMAC256 = 'KECCAK-KMAC-256';
  OSSL_DIGEST_NAME_SM3 = 'SM3';
  { MAC parameters }
  OSSL_MAC_PARAM_KEY = 'key';
  OSSL_MAC_PARAM_IV = 'iv';
  OSSL_MAC_PARAM_CUSTOM = 'custom';
  OSSL_MAC_PARAM_SALT = 'salt';
  OSSL_MAC_PARAM_XOF = 'xof';
  OSSL_MAC_PARAM_DIGEST_NOINIT = 'digest-noinit';
  OSSL_MAC_PARAM_DIGEST_ONESHOT = 'digest-oneshot';
  OSSL_MAC_PARAM_C_ROUNDS = 'c-rounds';
  OSSL_MAC_PARAM_D_ROUNDS = 'd-rounds';
  
  {* If "engine" or "properties" are specified, they should always be paired
  * with "cipher" or "digest".
  }
  OSSL_MAC_PARAM_CIPHER = OSSL_ALG_PARAM_CIPHER;
  OSSL_MAC_PARAM_DIGEST = OSSL_ALG_PARAM_DIGEST;
  OSSL_MAC_PARAM_PROPERTIES = OSSL_ALG_PARAM_PROPERTIES;
  OSSL_MAC_PARAM_SIZE = 'size';
  OSSL_MAC_PARAM_BLOCK_SIZE = 'block-size';
  OSSL_MAC_PARAM_TLS_DATA_SIZE = 'tls-data-size';
  { Known MAC names }
  OSSL_MAC_NAME_BLAKE2BMAC = 'BLAKE2BMAC';
  OSSL_MAC_NAME_BLAKE2SMAC = 'BLAKE2SMAC';
  OSSL_MAC_NAME_CMAC = 'CMAC';
  OSSL_MAC_NAME_GMAC = 'GMAC';
  OSSL_MAC_NAME_HMAC = 'HMAC';
  OSSL_MAC_NAME_KMAC128 = 'KMAC128';
  OSSL_MAC_NAME_KMAC256 = 'KMAC256';
  OSSL_MAC_NAME_POLY1305 = 'POLY1305';
  OSSL_MAC_NAME_SIPHASH = 'SIPHASH';
  { KDF / PRF parameters }
  OSSL_KDF_PARAM_SECRET = 'secret';
  OSSL_KDF_PARAM_KEY = 'key';
  OSSL_KDF_PARAM_SALT = 'salt';
  OSSL_KDF_PARAM_PASSWORD = 'pass';
  OSSL_KDF_PARAM_PREFIX = 'prefix';
  OSSL_KDF_PARAM_LABEL = 'label';
  OSSL_KDF_PARAM_DATA = 'data';
  OSSL_KDF_PARAM_DIGEST = OSSL_ALG_PARAM_DIGEST;
  OSSL_KDF_PARAM_CIPHER = OSSL_ALG_PARAM_CIPHER;
  OSSL_KDF_PARAM_MAC = OSSL_ALG_PARAM_MAC;
  OSSL_KDF_PARAM_MAC_SIZE = 'maclen';
  OSSL_KDF_PARAM_PROPERTIES = OSSL_ALG_PARAM_PROPERTIES;
  OSSL_KDF_PARAM_ITER = 'iter';
  OSSL_KDF_PARAM_MODE = 'mode';
  OSSL_KDF_PARAM_PKCS5 = 'pkcs5';
  OSSL_KDF_PARAM_UKM = 'ukm';
  OSSL_KDF_PARAM_CEK_ALG = 'cekalg';
  OSSL_KDF_PARAM_SCRYPT_N = 'n';
  OSSL_KDF_PARAM_SCRYPT_R = 'r';
  OSSL_KDF_PARAM_SCRYPT_P = 'p';
  OSSL_KDF_PARAM_SCRYPT_MAXMEM = 'maxmem_bytes';
  OSSL_KDF_PARAM_INFO = 'info';
  OSSL_KDF_PARAM_SEED = 'seed';
  OSSL_KDF_PARAM_SSHKDF_XCGHASH = 'xcghash';
  OSSL_KDF_PARAM_SSHKDF_SESSION_ID = 'session_id';
  OSSL_KDF_PARAM_SSHKDF_TYPE = 'type';
  OSSL_KDF_PARAM_SIZE = 'size';
  OSSL_KDF_PARAM_CONSTANT = 'constant';
  OSSL_KDF_PARAM_PKCS12_ID = 'id';
  OSSL_KDF_PARAM_KBKDF_USE_L = 'use-l';
  OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR = 'use-separator';
  OSSL_KDF_PARAM_X942_ACVPINFO = 'acvp-info';
  OSSL_KDF_PARAM_X942_PARTYUINFO = 'partyu-info';
  OSSL_KDF_PARAM_X942_PARTYVINFO = 'partyv-info';
  OSSL_KDF_PARAM_X942_SUPP_PUBINFO = 'supp-pubinfo';
  OSSL_KDF_PARAM_X942_SUPP_PRIVINFO = 'supp-privinfo';
  OSSL_KDF_PARAM_X942_USE_KEYBITS = 'use-keybits';
  { Known KDF names }
  OSSL_KDF_NAME_HKDF = 'HKDF';
  OSSL_KDF_NAME_TLS1_3_KDF = 'TLS13-KDF';
  OSSL_KDF_NAME_PBKDF1 = 'PBKDF1';
  OSSL_KDF_NAME_PBKDF2 = 'PBKDF2';
  OSSL_KDF_NAME_SCRYPT = 'SCRYPT';
  OSSL_KDF_NAME_SSHKDF = 'SSHKDF';
  OSSL_KDF_NAME_SSKDF = 'SSKDF';
  OSSL_KDF_NAME_TLS1_PRF = 'TLS1-PRF';
  OSSL_KDF_NAME_X942KDF_ASN1 = 'X942KDF-ASN1';
  OSSL_KDF_NAME_X942KDF_CONCAT = 'X942KDF-CONCAT';
  OSSL_KDF_NAME_X963KDF = 'X963KDF';
  OSSL_KDF_NAME_KBKDF = 'KBKDF';
  OSSL_KDF_NAME_KRB5KDF = 'KRB5KDF';
  { Known RAND names }
  OSSL_RAND_PARAM_STATE = 'state';
  OSSL_RAND_PARAM_STRENGTH = 'strength';
  OSSL_RAND_PARAM_MAX_REQUEST = 'max_request';
  OSSL_RAND_PARAM_TEST_ENTROPY = 'test_entropy';
  OSSL_RAND_PARAM_TEST_NONCE = 'test_nonce';
  { RAND/DRBG names }
  OSSL_DRBG_PARAM_RESEED_REQUESTS = 'reseed_requests';
  OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL = 'reseed_time_interval';
  OSSL_DRBG_PARAM_MIN_ENTROPYLEN = 'min_entropylen';
  OSSL_DRBG_PARAM_MAX_ENTROPYLEN = 'max_entropylen';
  OSSL_DRBG_PARAM_MIN_NONCELEN = 'min_noncelen';
  OSSL_DRBG_PARAM_MAX_NONCELEN = 'max_noncelen';
  OSSL_DRBG_PARAM_MAX_PERSLEN = 'max_perslen';
  OSSL_DRBG_PARAM_MAX_ADINLEN = 'max_adinlen';
  OSSL_DRBG_PARAM_RESEED_COUNTER = 'reseed_counter';
  OSSL_DRBG_PARAM_RESEED_TIME = 'reseed_time';
  OSSL_DRBG_PARAM_PROPERTIES = OSSL_ALG_PARAM_PROPERTIES;
  OSSL_DRBG_PARAM_DIGEST = OSSL_ALG_PARAM_DIGEST;
  OSSL_DRBG_PARAM_CIPHER = OSSL_ALG_PARAM_CIPHER;
  OSSL_DRBG_PARAM_MAC = OSSL_ALG_PARAM_MAC;
  OSSL_DRBG_PARAM_USE_DF = 'use_derivation_function';
  { DRBG call back parameters }
  OSSL_DRBG_PARAM_ENTROPY_REQUIRED = 'entropy_required';
  OSSL_DRBG_PARAM_PREDICTION_RESISTANCE = 'prediction_resistance';
  OSSL_DRBG_PARAM_MIN_LENGTH = 'minium_length';
  OSSL_DRBG_PARAM_MAX_LENGTH = 'maxium_length';
  OSSL_DRBG_PARAM_RANDOM_DATA = 'random_data';
  OSSL_DRBG_PARAM_SIZE = 'size';
  { PKEY parameters }
  { Common PKEY parameters }
  OSSL_PKEY_PARAM_BITS = 'bits';
  OSSL_PKEY_PARAM_MAX_SIZE = 'max-size';
  OSSL_PKEY_PARAM_SECURITY_BITS = 'security-bits';
  OSSL_PKEY_PARAM_DIGEST = OSSL_ALG_PARAM_DIGEST;
  OSSL_PKEY_PARAM_CIPHER = OSSL_ALG_PARAM_CIPHER;
  OSSL_PKEY_PARAM_ENGINE = OSSL_ALG_PARAM_ENGINE;
  OSSL_PKEY_PARAM_PROPERTIES = OSSL_ALG_PARAM_PROPERTIES;
  OSSL_PKEY_PARAM_DEFAULT_DIGEST = 'default-digest';
  OSSL_PKEY_PARAM_MANDATORY_DIGEST = 'mandatory-digest';
  OSSL_PKEY_PARAM_PAD_MODE = 'pad-mode';
  OSSL_PKEY_PARAM_DIGEST_SIZE = 'digest-size';
  OSSL_PKEY_PARAM_MASKGENFUNC = 'mgf';
  OSSL_PKEY_PARAM_MGF1_DIGEST = 'mgf1-digest';
  OSSL_PKEY_PARAM_MGF1_PROPERTIES = 'mgf1-properties';
  OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY = 'encoded-pub-key';
  OSSL_PKEY_PARAM_GROUP_NAME = 'group';
  OSSL_PKEY_PARAM_DIST_ID = 'distid';
  OSSL_PKEY_PARAM_PUB_KEY = 'pub';
  OSSL_PKEY_PARAM_PRIV_KEY = 'priv';
  { Diffie-Hellman/DSA Parameters }
  OSSL_PKEY_PARAM_FFC_P = 'p';
  OSSL_PKEY_PARAM_FFC_G = 'g';
  OSSL_PKEY_PARAM_FFC_Q = 'q';
  OSSL_PKEY_PARAM_FFC_GINDEX = 'gindex';
  OSSL_PKEY_PARAM_FFC_PCOUNTER = 'pcounter';
  OSSL_PKEY_PARAM_FFC_SEED = 'seed';
  OSSL_PKEY_PARAM_FFC_COFACTOR = 'j';
  OSSL_PKEY_PARAM_FFC_H = 'hindex';
  OSSL_PKEY_PARAM_FFC_VALIDATE_PQ = 'validate-pq';
  OSSL_PKEY_PARAM_FFC_VALIDATE_G = 'validate-g';
  OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY = 'validate-legacy';
  { Diffie-Hellman params }
  OSSL_PKEY_PARAM_DH_GENERATOR = 'safeprime-generator';
  OSSL_PKEY_PARAM_DH_PRIV_LEN = 'priv_len';
  { Elliptic Curve Domain Parameters }
  OSSL_PKEY_PARAM_EC_PUB_X = 'qx';
  OSSL_PKEY_PARAM_EC_PUB_Y = 'qy';
  { Elliptic Curve Explicit Domain Parameters }
  OSSL_PKEY_PARAM_EC_FIELD_TYPE = 'field-type';
  OSSL_PKEY_PARAM_EC_P = 'p';
  OSSL_PKEY_PARAM_EC_A = 'a';
  OSSL_PKEY_PARAM_EC_B = 'b';
  OSSL_PKEY_PARAM_EC_GENERATOR = 'generator';
  OSSL_PKEY_PARAM_EC_ORDER = 'order';
  OSSL_PKEY_PARAM_EC_COFACTOR = 'cofactor';
  OSSL_PKEY_PARAM_EC_SEED = 'seed';
  OSSL_PKEY_PARAM_EC_CHAR2_M = 'm';
  OSSL_PKEY_PARAM_EC_CHAR2_TYPE = 'basis-type';
  OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS = 'tp';
  OSSL_PKEY_PARAM_EC_CHAR2_PP_K1 = 'k1';
  OSSL_PKEY_PARAM_EC_CHAR2_PP_K2 = 'k2';
  OSSL_PKEY_PARAM_EC_CHAR2_PP_K3 = 'k3';
  OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS = 'decoded-from-explicit';
  { Elliptic Curve Key Parameters }
  OSSL_PKEY_PARAM_USE_COFACTOR_FLAG = 'use-cofactor-flag';
  OSSL_PKEY_PARAM_USE_COFACTOR_ECDH = OSSL_PKEY_PARAM_USE_COFACTOR_FLAG;
  { RSA Keys }
  
  {* n, e, d are the usual public and private key components
  *
  * rsa-num is the number of factors, including p and q
  * rsa-factor is used for each factor: p, q, r_i (i = 3, ...)
  * rsa-exponent is used for each exponent: dP, dQ, d_i (i = 3, ...)
  * rsa-coefficient is used for each coefficient: qInv, t_i (i = 3, ...)
  *
  * The number of rsa-factor items must be equal to the number of rsa-exponent
  * items, and the number of rsa-coefficients must be one less.
  * (the base i for the coefficients is 2, not 1, at least as implied by
  * RFC 8017)
  }
  OSSL_PKEY_PARAM_RSA_N = 'n';
  OSSL_PKEY_PARAM_RSA_E = 'e';
  OSSL_PKEY_PARAM_RSA_D = 'd';
  OSSL_PKEY_PARAM_RSA_FACTOR = 'rsa-factor';
  OSSL_PKEY_PARAM_RSA_EXPONENT = 'rsa-exponent';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT = 'rsa-coefficient';
  OSSL_PKEY_PARAM_RSA_FACTOR1 = OSSL_PKEY_PARAM_RSA_FACTOR + '1';
  OSSL_PKEY_PARAM_RSA_FACTOR2 = OSSL_PKEY_PARAM_RSA_FACTOR + '2';
  OSSL_PKEY_PARAM_RSA_FACTOR3 = OSSL_PKEY_PARAM_RSA_FACTOR + '3';
  OSSL_PKEY_PARAM_RSA_FACTOR4 = OSSL_PKEY_PARAM_RSA_FACTOR + '4';
  OSSL_PKEY_PARAM_RSA_FACTOR5 = OSSL_PKEY_PARAM_RSA_FACTOR + '5';
  OSSL_PKEY_PARAM_RSA_FACTOR6 = OSSL_PKEY_PARAM_RSA_FACTOR + '6';
  OSSL_PKEY_PARAM_RSA_FACTOR7 = OSSL_PKEY_PARAM_RSA_FACTOR + '7';
  OSSL_PKEY_PARAM_RSA_FACTOR8 = OSSL_PKEY_PARAM_RSA_FACTOR + '8';
  OSSL_PKEY_PARAM_RSA_FACTOR9 = OSSL_PKEY_PARAM_RSA_FACTOR + '9';
  OSSL_PKEY_PARAM_RSA_FACTOR10 = OSSL_PKEY_PARAM_RSA_FACTOR + '10';
  OSSL_PKEY_PARAM_RSA_EXPONENT1 = OSSL_PKEY_PARAM_RSA_EXPONENT + '1';
  OSSL_PKEY_PARAM_RSA_EXPONENT2 = OSSL_PKEY_PARAM_RSA_EXPONENT + '2';
  OSSL_PKEY_PARAM_RSA_EXPONENT3 = OSSL_PKEY_PARAM_RSA_EXPONENT + '3';
  OSSL_PKEY_PARAM_RSA_EXPONENT4 = OSSL_PKEY_PARAM_RSA_EXPONENT + '4';
  OSSL_PKEY_PARAM_RSA_EXPONENT5 = OSSL_PKEY_PARAM_RSA_EXPONENT + '5';
  OSSL_PKEY_PARAM_RSA_EXPONENT6 = OSSL_PKEY_PARAM_RSA_EXPONENT + '6';
  OSSL_PKEY_PARAM_RSA_EXPONENT7 = OSSL_PKEY_PARAM_RSA_EXPONENT + '7';
  OSSL_PKEY_PARAM_RSA_EXPONENT8 = OSSL_PKEY_PARAM_RSA_EXPONENT + '8';
  OSSL_PKEY_PARAM_RSA_EXPONENT9 = OSSL_PKEY_PARAM_RSA_EXPONENT + '9';
  OSSL_PKEY_PARAM_RSA_EXPONENT10 = OSSL_PKEY_PARAM_RSA_EXPONENT + '10';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT1 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '1';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT2 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '2';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT3 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '3';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT4 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '4';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT5 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '5';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT6 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '6';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT7 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '7';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT8 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '8';
  OSSL_PKEY_PARAM_RSA_COEFFICIENT9 = OSSL_PKEY_PARAM_RSA_COEFFICIENT + '9';
  { RSA padding modes }
  OSSL_PKEY_RSA_PAD_MODE_NONE = 'none';
  OSSL_PKEY_RSA_PAD_MODE_PKCSV15 = 'pkcs1';
  OSSL_PKEY_RSA_PAD_MODE_OAEP = 'oaep';
  OSSL_PKEY_RSA_PAD_MODE_X931 = 'x931';
  OSSL_PKEY_RSA_PAD_MODE_PSS = 'pss';
  { RSA pss padding salt length }
  OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST = 'digest';
  OSSL_PKEY_RSA_PSS_SALT_LEN_MAX = 'max';
  OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO = 'auto';
  { Key generation parameters }
  OSSL_PKEY_PARAM_RSA_BITS = OSSL_PKEY_PARAM_BITS;
  OSSL_PKEY_PARAM_RSA_PRIMES = 'primes';
  OSSL_PKEY_PARAM_RSA_DIGEST = OSSL_PKEY_PARAM_DIGEST;
  OSSL_PKEY_PARAM_RSA_DIGEST_PROPS = OSSL_PKEY_PARAM_PROPERTIES;
  OSSL_PKEY_PARAM_RSA_MASKGENFUNC = OSSL_PKEY_PARAM_MASKGENFUNC;
  OSSL_PKEY_PARAM_RSA_MGF1_DIGEST = OSSL_PKEY_PARAM_MGF1_DIGEST;
  OSSL_PKEY_PARAM_RSA_PSS_SALTLEN = 'saltlen';
  { Key generation parameters }
  OSSL_PKEY_PARAM_FFC_TYPE = 'type';
  OSSL_PKEY_PARAM_FFC_PBITS = 'pbits';
  OSSL_PKEY_PARAM_FFC_QBITS = 'qbits';
  OSSL_PKEY_PARAM_FFC_DIGEST = OSSL_PKEY_PARAM_DIGEST;
  OSSL_PKEY_PARAM_FFC_DIGEST_PROPS = OSSL_PKEY_PARAM_PROPERTIES;
  OSSL_PKEY_PARAM_EC_ENCODING = 'encoding';
  OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT = 'point-format';
  OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE = 'group-check';
  OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC = 'include-public';
  { OSSL_PKEY_PARAM_EC_ENCODING values }
  OSSL_PKEY_EC_ENCODING_EXPLICIT = 'explicit';
  OSSL_PKEY_EC_ENCODING_GROUP = 'named_curve';
  OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED = 'uncompressed';
  OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED = 'compressed';
  OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID = 'hybrid';
  OSSL_PKEY_EC_GROUP_CHECK_DEFAULT = 'default';
  OSSL_PKEY_EC_GROUP_CHECK_NAMED = 'named';
  OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST = 'named-nist';
  { Key Exchange parameters }
  OSSL_EXCHANGE_PARAM_PAD = 'pad';
  OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE = 'ecdh-cofactor-mode';
  OSSL_EXCHANGE_PARAM_KDF_TYPE = 'kdf-type';
  OSSL_EXCHANGE_PARAM_KDF_DIGEST = 'kdf-digest';
  OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS = 'kdf-digest-props';
  OSSL_EXCHANGE_PARAM_KDF_OUTLEN = 'kdf-outlen';
  { The following parameter is an octet_string on set and an octet_ptr on get }
  OSSL_EXCHANGE_PARAM_KDF_UKM = 'kdf-ukm';
  { Signature parameters }
  OSSL_SIGNATURE_PARAM_ALGORITHM_ID = 'algorithm-id';
  OSSL_SIGNATURE_PARAM_PAD_MODE = OSSL_PKEY_PARAM_PAD_MODE;
  OSSL_SIGNATURE_PARAM_DIGEST = OSSL_PKEY_PARAM_DIGEST;
  OSSL_SIGNATURE_PARAM_PROPERTIES = OSSL_PKEY_PARAM_PROPERTIES;
  OSSL_SIGNATURE_PARAM_PSS_SALTLEN = 'saltlen';
  OSSL_SIGNATURE_PARAM_MGF1_DIGEST = OSSL_PKEY_PARAM_MGF1_DIGEST;
  OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES = OSSL_PKEY_PARAM_MGF1_PROPERTIES;
  OSSL_SIGNATURE_PARAM_DIGEST_SIZE = OSSL_PKEY_PARAM_DIGEST_SIZE;
  { Asym cipher parameters }
  OSSL_ASYM_CIPHER_PARAM_DIGEST = OSSL_PKEY_PARAM_DIGEST;
  OSSL_ASYM_CIPHER_PARAM_PROPERTIES = OSSL_PKEY_PARAM_PROPERTIES;
  OSSL_ASYM_CIPHER_PARAM_ENGINE = OSSL_PKEY_PARAM_ENGINE;
  OSSL_ASYM_CIPHER_PARAM_PAD_MODE = OSSL_PKEY_PARAM_PAD_MODE;
  OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST = OSSL_PKEY_PARAM_MGF1_DIGEST;
  OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS = OSSL_PKEY_PARAM_MGF1_PROPERTIES;
  OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST = OSSL_ALG_PARAM_DIGEST;
  OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS = 'digest-props';
  { The following parameter is an octet_string on set and an octet_ptr on get }
  OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL = 'oaep-label';
  OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION = 'tls-client-version';
  OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION = 'tls-negotiated-version';
  
  {* Encoder / decoder parameters
  }
  OSSL_ENCODER_PARAM_CIPHER = OSSL_ALG_PARAM_CIPHER;
  OSSL_ENCODER_PARAM_PROPERTIES = OSSL_ALG_PARAM_PROPERTIES;
  { Currently PVK only, but reusable for others as needed }
  OSSL_ENCODER_PARAM_ENCRYPT_LEVEL = 'encrypt-level';
  OSSL_ENCODER_PARAM_SAVE_PARAMETERS = 'save-parameters';
  OSSL_DECODER_PARAM_PROPERTIES = OSSL_ALG_PARAM_PROPERTIES;
  { Passphrase callback parameters }
  OSSL_PASSPHRASE_PARAM_INFO = 'info';
  { Keygen callback parameters, from provider to libcrypto }
  OSSL_GEN_PARAM_POTENTIAL = 'potential';
  OSSL_GEN_PARAM_ITERATION = 'iteration';
  { ACVP Test parameters : These should not be used normally }
  OSSL_PKEY_PARAM_RSA_TEST_XP1 = 'xp1';
  OSSL_PKEY_PARAM_RSA_TEST_XP2 = 'xp2';
  OSSL_PKEY_PARAM_RSA_TEST_XP = 'xp';
  OSSL_PKEY_PARAM_RSA_TEST_XQ1 = 'xq1';
  OSSL_PKEY_PARAM_RSA_TEST_XQ2 = 'xq2';
  OSSL_PKEY_PARAM_RSA_TEST_XQ = 'xq';
  OSSL_PKEY_PARAM_RSA_TEST_P1 = 'p1';
  OSSL_PKEY_PARAM_RSA_TEST_P2 = 'p2';
  OSSL_PKEY_PARAM_RSA_TEST_Q1 = 'q1';
  OSSL_PKEY_PARAM_RSA_TEST_Q2 = 'q2';
  OSSL_SIGNATURE_PARAM_KAT = 'kat';
  { KEM parameters }
  OSSL_KEM_PARAM_OPERATION = 'operation';
  { OSSL_KEM_PARAM_OPERATION values }
  OSSL_KEM_PARAM_OPERATION_RSASVE = 'RSASVE';
  { Capabilities }
  { TLS-GROUP Capability }
  OSSL_CAPABILITY_TLS_GROUP_NAME = 'tls-group-name';
  OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL = 'tls-group-name-internal';
  OSSL_CAPABILITY_TLS_GROUP_ID = 'tls-group-id';
  OSSL_CAPABILITY_TLS_GROUP_ALG = 'tls-group-alg';
  OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS = 'tls-group-sec-bits';
  OSSL_CAPABILITY_TLS_GROUP_IS_KEM = 'tls-group-is-kem';
  OSSL_CAPABILITY_TLS_GROUP_MIN_TLS = 'tls-min-tls';
  OSSL_CAPABILITY_TLS_GROUP_MAX_TLS = 'tls-max-tls';
  OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS = 'tls-min-dtls';
  OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS = 'tls-max-dtls';
  {-
  * storemgmt parameters
  }
  
  {* Used by storemgmt_ctx_set_params():
  *
  * - OSSL_STORE_PARAM_EXPECT is an INTEGER, and the value is any of the
  *   OSSL_STORE_INFO numbers.  This is used to set the expected type of
  *   object loaded.
  *
  * - OSSL_STORE_PARAM_SUBJECT, OSSL_STORE_PARAM_ISSUER,
  *   OSSL_STORE_PARAM_SERIAL, OSSL_STORE_PARAM_FINGERPRINT,
  *   OSSL_STORE_PARAM_DIGEST, OSSL_STORE_PARAM_ALIAS
  *   are used as search criteria.
  *   (OSSL_STORE_PARAM_DIGEST is used with OSSL_STORE_PARAM_FINGERPRINT)
  }
  OSSL_STORE_PARAM_EXPECT = 'expect';
  OSSL_STORE_PARAM_SUBJECT = 'subject';
  OSSL_STORE_PARAM_ISSUER = 'name';
  OSSL_STORE_PARAM_SERIAL = 'serial';
  OSSL_STORE_PARAM_DIGEST = 'digest';
  OSSL_STORE_PARAM_FINGERPRINT = 'fingerprint';
  OSSL_STORE_PARAM_ALIAS = 'alias';
  { You may want to pass properties for the provider implementation to use }
  OSSL_STORE_PARAM_PROPERTIES = 'properties';
  { OSSL_DECODER input type if a decoder is used by the store }
  OSSL_STORE_PARAM_INPUT_TYPE = 'input-type';
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



