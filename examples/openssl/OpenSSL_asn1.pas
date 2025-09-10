(* This unit was generated from the source file asn1.h2pas 
It should not be modified directly. All changes should be made to asn1.h2pas
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


unit OpenSSL_asn1;


interface

// Headers for OpenSSL 1.1.1
// asn1.h


uses
  OpenSSLAPI,
  OpenSSL_asn1t,
  OpenSSL_bio,
  OpenSSL_ossl_typ;

{$MINENUMSIZE 4}

const
  (*
   * NB the constants below are used internally by ASN1_INTEGER
   * and ASN1_ENUMERATED to indicate the sign. They are *not* on
   * the wire tag values.
   *)

  V_ASN1_NEG = $100;
  V_ASN1_NEG_INTEGER = 2 or V_ASN1_NEG;
  V_ASN1_NEG_ENUMERATED = 10 or V_ASN1_NEG;

  (* For use with d2i_ASN1_type_bytes() *)
  B_ASN1_NUMERICSTRING = $0001;
  B_ASN1_PRINTABLESTRING = $0002;
  B_ASN1_T61STRING = $0004;
  B_ASN1_TELETEXSTRING = $0004;
  B_ASN1_VIDEOTEXSTRING = $0008;
  B_ASN1_IA5STRING = $0010;
  B_ASN1_GRAPHICSTRING = $0020;
  B_ASN1_ISO64STRING = $0040;
  B_ASN1_VISIBLESTRING = $0040;
  B_ASN1_GENERALSTRING = $0080;
  B_ASN1_UNIVERSALSTRING = $0100;
  B_ASN1_OCTET_STRING = $0200;
  B_ASN1_BIT_STRING = $0400;
  B_ASN1_BMPSTRING = $0800;
  B_ASN1_UNKNOWN = $1000;
  B_ASN1_UTF8STRING = $2000;
  B_ASN1_UTCTIME = $4000;
  B_ASN1_GENERALIZEDTIME = $8000;
  B_ASN1_SEQUENCE = $10000;
 (* For use with ASN1_mbstring_copy() *)
  MBSTRING_FLAG = $1000;
  MBSTRING_UTF8 = MBSTRING_FLAG;
  MBSTRING_ASC = MBSTRING_FLAG or 1;
  MBSTRING_BMP = MBSTRING_FLAG or 2;
  MBSTRING_UNIV = MBSTRING_FLAG or 4;
  SMIME_OLDMIME = $400;
  SMIME_CRLFEOL = $800;
  SMIME_STREAM = $1000;

//    struct X509_algor_st;
//DEFINE_STACK_OF(X509_ALGOR)

  ASN1_STRING_FLAG_BITS_LEFT = $08;   (* Set if $07 has bits left value *)
  (*
   * This indicates that the ASN1_STRING is not a real value but just a place
   * holder for the location where indefinite length constructed data should be
   * inserted in the memory buffer
   *)
  ASN1_STRING_FLAG_NDEF = $010;

  (*
   * This flag is used by the CMS code to indicate that a string is not
   * complete and is a place holder for content when it had all been accessed.
   * The flag will be reset when content has been written to it.
   *)

  ASN1_STRING_FLAG_CONT = $020;
  (*
   * This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
   * type.
   *)
  ASN1_STRING_FLAG_MSTRING = $040;
  (* String is embedded and only content should be freed *)
  ASN1_STRING_FLAG_EMBED = $080;
  (* String should be parsed in RFC 5280's time format *)
  ASN1_STRING_FLAG_X509_TIME = $100;

  (* Used with ASN1 LONG type: if a long is set to this it is omitted *)
  ASN1_LONG_UNDEF = TOpenSSL_C_LONG($7fffffff);

  STABLE_FLAGS_MALLOC = $01;
  (*
   * A zero passed to ASN1_STRING_TABLE_new_add for the flags is interpreted
   * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
   * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
   * STABLE_FLAGS_CLEAR to reflect this.
   *)
  STABLE_FLAGS_CLEAR = STABLE_FLAGS_MALLOC;
  STABLE_NO_MASK = $02;
  DIRSTRING_TYPE = B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;
  PKCS9STRING_TYPE = DIRSTRING_TYPE or B_ASN1_IA5STRING;

  (* size limits: this stuff is taken straight from RFC2459 *)
  ub_name = 32768;
  ub_common_name = 64;
  ub_locality_name = 128;
  ub_state_name = 128;
  ub_organization_name = 64;
  ub_organization_unit_name = 64;
  ub_title = 64;
  ub_email_address = 128;

  (* Parameters used by ASN1_STRING_print_ex() *)

  (*
   * These determine which characters to escape: RFC2253 special characters,
   * control characters and MSB set characters
   *)
  ASN1_STRFLGS_ESC_2253 = 1;
  ASN1_STRFLGS_ESC_CTRL = 2;
  ASN1_STRFLGS_ESC_MSB = 4;

  (*
   * This flag determines how we do escaping: normally RC2253 backslash only,
   * set this to use backslash and quote.
   *)

  ASN1_STRFLGS_ESC_QUOTE = 8;

  (* These three flags are internal use only. *)

  (* Character is a valid PrintableString character *)
  CHARTYPE_PRINTABLESTRING = $10;
  (* Character needs escaping if it is the first character *)
  CHARTYPE_FIRST_ESC_2253 = $20;
  (* Character needs escaping if it is the last character *)
  CHARTYPE_LAST_ESC_2253 = $40;

  (*
   * NB the internal flags are safely reused below by flags handled at the top
   * level.
   *)

  (*
   * If this is set we convert all character strings to UTF8 first
   *)

  ASN1_STRFLGS_UTF8_CONVERT = $10;

  (*
   * If this is set we don't attempt to interpret content: just assume all
   * strings are 1 byte per character. This will produce some pretty odd
   * looking output!
   *)

  ASN1_STRFLGS_IGNORE_TYPE = $20;

  (* If this is set we include the string type in the output *)
  ASN1_STRFLGS_SHOW_TYPE = $40;

  (*
   * This determines which strings to display and which to 'dump' (hex dump of
   * content octets or DER encoding). We can only dump non character strings or
   * everything. If we don't dump 'unknown' they are interpreted as character
   * strings with 1 octet per character and are subject to the usual escaping
   * options.
   *)

  ASN1_STRFLGS_DUMP_ALL = $80;
  ASN1_STRFLGS_DUMP_UNKNOWN = $100;

  (*
   * These determine what 'dumping' does, we can dump the content octets or the
   * DER encoding: both use the RFC2253 #XXXXX notation.
   *)

  ASN1_STRFLGS_DUMP_DER = $200;

  (*
   * This flag specifies that RC2254 escaping shall be performed.
   *)

  ASN1_STRFLGS_ESC_2254 = $400;

  (*
   * All the string flags consistent with RFC2253, escaping control characters
   * isn't essential in RFC2253 but it is advisable anyway.
   *)

  ASN1_STRFLGS_RFC2253 = ASN1_STRFLGS_ESC_2253 or ASN1_STRFLGS_ESC_CTRL or
    ASN1_STRFLGS_ESC_MSB or ASN1_STRFLGS_UTF8_CONVERT or
    ASN1_STRFLGS_DUMP_UNKNOWN or ASN1_STRFLGS_DUMP_DER;

  B_ASN1_TIME = B_ASN1_UTCTIME or B_ASN1_GENERALIZEDTIME;

  B_ASN1_PRINTABLE = B_ASN1_NUMERICSTRING or B_ASN1_PRINTABLESTRING or
    B_ASN1_T61STRING or B_ASN1_IA5STRING or B_ASN1_BIT_STRING or
    B_ASN1_UNIVERSALSTRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING or
    B_ASN1_SEQUENCE or B_ASN1_UNKNOWN;

  B_ASN1_DIRECTORYSTRING = B_ASN1_PRINTABLESTRING or B_ASN1_TELETEXSTRING or
    B_ASN1_BMPSTRING or B_ASN1_UNIVERSALSTRING or B_ASN1_UTF8STRING;

  B_ASN1_DISPLAYTEXT = B_ASN1_IA5STRING or B_ASN1_VISIBLESTRING or
    B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;

  (* ASN1 Print flags *)
  (* Indicate missing OPTIONAL fields *)
  ASN1_PCTX_FLAGS_SHOW_ABSENT = $001;
  (* Mark start and end of SEQUENCE *)
  ASN1_PCTX_FLAGS_SHOW_SEQUENCE = $002;
  (* Mark start and end of SEQUENCE/SET OF *)
  ASN1_PCTX_FLAGS_SHOW_SSOF = $004;
  (* Show the ASN1 type of primitives *)
  ASN1_PCTX_FLAGS_SHOW_TYPE = $008;
  (* Don't show ASN1 type of ANY *)
  ASN1_PCTX_FLAGS_NO_ANY_TYPE = $010;
  (* Don't show ASN1 type of MSTRINGs *)
  ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = $020;
  (* Don't show field names in SEQUENCE *)
  ASN1_PCTX_FLAGS_NO_FIELD_NAME = $040;
  (* Show structure names of each SEQUENCE field *)
  ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = $080;
  (* Don't show structure name even at top level *)
  ASN1_PCTX_FLAGS_NO_STRUCT_NAME = $100;

type
// Moved to ossl_type to prevent circular references
///(* This is the base type that holds just about everything :-) *)
//  asn1_string_st = record
//    length: TOpenSSL_C_int;
//    type_: TOpenSSL_C_int;
//    data: PByte;
//    (*
//     * The value of the following field depends on the type being held.  It
//     * is mostly being used for BIT_STRING so if the input data has a
//     * non-zero 'unused bits' value, it will be handled correctly
//     *)
//    flags: TOpenSSL_C_long;
//  end;

  pxnew = function: Pointer; cdecl;

  (*
   * ASN1_ENCODING structure: this is used to save the received encoding of an
   * ASN1 type. This is useful to get round problems with invalid encodings
   * which can break signatures.
   *)

  ASN1_ENCODING_st = record
    enc: PAnsiChar;           (* DER encoding *)
    len: TOpenSSL_C_LONG;                     (* Length of encoding *)
    modified: TOpenSSL_C_INT;                 (* set to 1 if 'enc' is invalid *)
  end;
  ASN1_ENCODING = ASN1_ENCODING_st;

  asn1_string_table_st = record
    nid: TOpenSSL_C_INT;
    minsize: TOpenSSL_C_LONG;
    maxsize: TOpenSSL_C_LONG;
    mask: TOpenSSL_C_ULONG;
    flags: TOpenSSL_C_ULONG;
  end;
  ASN1_STRING_TABLE = asn1_string_table_st;
  PASN1_STRING_TABLE = ^ASN1_STRING_TABLE;

// DEFINE_STACK_OF(ASN1_STRING_TABLE)

  (*                  !!!
   * Declarations for template structures: for full definitions see asn1t.h
   *)
  (* This is just an opaque pointer *)
// typedef struct ASN1_VALUE_st ASN1_VALUE;

  (* Declare ASN1 functions: the implement macro in in asn1t.h *)

//# define DECLARE_ASN1_FUNCTIONS(type) DECLARE_ASN1_FUNCTIONS_name(type, type)
//
//# define DECLARE_ASN1_ALLOC_FUNCTIONS(type) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, type)
//
//# define DECLARE_ASN1_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS(type, name, name)
//
//# define DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)
//
//# define DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name) \
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(type *a, unsigned char **out); \
//        DECLARE_ASN1_ITEM(itname)
//
//# define DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(const type *a, unsigned char **out); \
//        DECLARE_ASN1_ITEM(name)
//
//# define DECLARE_ASN1_NDEF_FUNCTION(name) \
//        int i2d_##name##_NDEF(name *a, unsigned char **out);
//
//# define DECLARE_ASN1_FUNCTIONS_const(name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS(name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)
//
//# define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        type *name##_new(void); \
//        void name##_free(type *a);
//
//# define DECLARE_ASN1_PRINT_FUNCTION(stname) \
//        DECLARE_ASN1_PRINT_FUNCTION_fname(stname, stname)
//
//# define DECLARE_ASN1_PRINT_FUNCTION_fname(stname, fname) \
//        int fname##_print_ctx(BIO *out, stname *x, int indent, \
//                                         const ASN1_PCTX *pctx);
//
//# define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
//# define I2D_OF(type) int (*)(type *,unsigned char **)
//# define I2D_OF_const(type) int (*)(const type *,unsigned char **)
//
//# define CHECKED_D2I_OF(type, d2i) \
//    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
//# define CHECKED_I2D_OF(type, i2d) \
//    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
//# define CHECKED_NEW_OF(type, xnew) \
//    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
//# define CHECKED_PTR_OF(type, p) \
//    ((void*) (1 ? p : (type*)0))
//# define CHECKED_PPTR_OF(type, p) \
//    ((void**) (1 ? p : (type**)0))
//
//# define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
//# define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type *,unsigned char **)
//# define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)
//
//TYPEDEF_D2I2D_OF(void);

  (*-
   * The following macros and typedefs allow an ASN1_ITEM
   * to be embedded in a structure and referenced. Since
   * the ASN1_ITEM pointers need to be globally accessible
   * (possibly from shared libraries) they may exist in
   * different forms. On platforms that support it the
   * ASN1_ITEM structure itself will be globally exported.
   * Other platforms will export a function that returns
   * an ASN1_ITEM pointer.
   *
   * To handle both cases transparently the macros below
   * should be used instead of hard coding an ASN1_ITEM
   * pointer in a structure.
   *
   * The structure will look like this:
   *
   * typedef struct SOMETHING_st {
   *      ...
   *      ASN1_ITEM_EXP *iptr;
   *      ...
   * } SOMETHING;
   *
   * It would be initialised as e.g.:
   *
   * SOMETHING somevar = {...,ASN1_ITEM_ref(X509),...};
   *
   * and the actual pointer extracted with:
   *
   * const ASN1_ITEM *it = ASN1_ITEM_ptr(somevar.iptr);
   *
   * Finally an ASN1_ITEM pointer can be extracted from an
   * appropriate reference with: ASN1_ITEM_rptr(X509). This
   * would be used when a function takes an ASN1_ITEM * argument.
   *
   *)

// # ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

///(* ASN1_ITEM pointer exported type *)
//typedef const ASN1_ITEM ASN1_ITEM_EXP;
//
///(* Macro to obtain ASN1_ITEM pointer from exported type *)
//#  define ASN1_ITEM_ptr(iptr) (iptr)
//
// (* Macro to include ASN1_ITEM pointer from base type *)
//#  define ASN1_ITEM_ref(iptr) (&(iptr##_it))
//
//#  define ASN1_ITEM_rptr(ref) (&(ref##_it))
//
//#  define DECLARE_ASN1_ITEM(name) \
//        OPENSSL_EXTERN const ASN1_ITEM name##_it;
//
//# else

// (*
// * Platforms that can't easily handle shared global variables are declared as
// * functions returning ASN1_ITEM pointers.
// *)

///(* ASN1_ITEM pointer exported type *)
//typedef const ASN1_ITEM *ASN1_ITEM_EXP (void);
//
///(* Macro to obtain ASN1_ITEM pointer from exported type *)
//#  define ASN1_ITEM_ptr(iptr) (iptr())
//
///(* Macro to include ASN1_ITEM pointer from base type *)
//#  define ASN1_ITEM_ref(iptr) (iptr##_it)
//
//#  define ASN1_ITEM_rptr(ref) (ref##_it())
//
//#  define DECLARE_ASN1_ITEM(name) \
//        const ASN1_ITEM * name##_it(void);
//
//# endif

//DEFINE_STACK_OF(ASN1_INTEGER)
//
//DEFINE_STACK_OF(ASN1_GENERALSTRING)
//
//DEFINE_STACK_OF(ASN1_UTF8STRING)

//DEFINE_STACK_OF(ASN1_TYPE)
//
//typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
//
//DECLARE_ASN1_ENCODE_FUNCTIONS_const(ASN1_SEQUENCE_ANY, ASN1_SEQUENCE_ANY)
//DECLARE_ASN1_ENCODE_FUNCTIONS_const(ASN1_SEQUENCE_ANY, ASN1_SET_ANY)

  (* This is used to contain a list of bit names *)

  BIT_STRING_BITNAME_st = record
    bitnum: TOpenSSL_C_INT;
    lname: PAnsiChar;
    sname: PAnsiChar;
  end;
  BIT_STRING_BITNAME = BIT_STRING_BITNAME_st;
  PBIT_STRING_BITNAME = ^BIT_STRING_BITNAME;

//DECLARE_ASN1_FUNCTIONS(type) -->
//        type *name##_new(void); \
//        void name##_free(type *a);
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(type *a, unsigned char **out); \
//#  define DECLARE_ASN1_ITEM(name) \
//        OPENSSL_EXTERN const ASN1_ITEM name##_it;

// DECLARE_ASN1_FUNCTIONS_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ASN1_TYPE_get}
{$EXTERNALSYM ASN1_TYPE_set}
{$EXTERNALSYM ASN1_TYPE_set1}
{$EXTERNALSYM ASN1_TYPE_cmp}
{$EXTERNALSYM ASN1_TYPE_pack_sequence}
{$EXTERNALSYM ASN1_TYPE_unpack_sequence}
{$EXTERNALSYM ASN1_OBJECT_new}
{$EXTERNALSYM ASN1_OBJECT_free}
{$EXTERNALSYM i2d_ASN1_OBJECT}
{$EXTERNALSYM d2i_ASN1_OBJECT}
{$EXTERNALSYM ASN1_STRING_new}
{$EXTERNALSYM ASN1_STRING_free}
{$EXTERNALSYM ASN1_STRING_clear_free}
{$EXTERNALSYM ASN1_STRING_copy}
{$EXTERNALSYM ASN1_STRING_dup}
{$EXTERNALSYM ASN1_STRING_type_new}
{$EXTERNALSYM ASN1_STRING_cmp}
{$EXTERNALSYM ASN1_STRING_set}
{$EXTERNALSYM ASN1_STRING_set0}
{$EXTERNALSYM ASN1_STRING_length}
{$EXTERNALSYM ASN1_STRING_length_set}
{$EXTERNALSYM ASN1_STRING_type}
{$EXTERNALSYM ASN1_STRING_get0_data}
{$EXTERNALSYM ASN1_BIT_STRING_set}
{$EXTERNALSYM ASN1_BIT_STRING_set_bit}
{$EXTERNALSYM ASN1_BIT_STRING_get_bit}
{$EXTERNALSYM ASN1_BIT_STRING_check}
{$EXTERNALSYM ASN1_BIT_STRING_name_print}
{$EXTERNALSYM ASN1_BIT_STRING_num_asc}
{$EXTERNALSYM ASN1_BIT_STRING_set_asc}
{$EXTERNALSYM ASN1_INTEGER_new}
{$EXTERNALSYM ASN1_INTEGER_free}
{$EXTERNALSYM d2i_ASN1_INTEGER}
{$EXTERNALSYM i2d_ASN1_INTEGER}
{$EXTERNALSYM d2i_ASN1_UINTEGER}
{$EXTERNALSYM ASN1_INTEGER_dup}
{$EXTERNALSYM ASN1_INTEGER_cmp}
{$EXTERNALSYM ASN1_UTCTIME_check}
{$EXTERNALSYM ASN1_UTCTIME_set}
{$EXTERNALSYM ASN1_UTCTIME_adj}
{$EXTERNALSYM ASN1_UTCTIME_set_string}
{$EXTERNALSYM ASN1_UTCTIME_cmp_time_t}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_check}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_set}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_adj}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_set_string}
{$EXTERNALSYM ASN1_TIME_diff}
{$EXTERNALSYM ASN1_OCTET_STRING_dup}
{$EXTERNALSYM ASN1_OCTET_STRING_cmp}
{$EXTERNALSYM ASN1_OCTET_STRING_set}
{$EXTERNALSYM ASN1_OCTET_STRING_new}
{$EXTERNALSYM ASN1_OCTET_STRING_free}
{$EXTERNALSYM d2i_ASN1_OCTET_STRING}
{$EXTERNALSYM i2d_ASN1_OCTET_STRING}
{$EXTERNALSYM UTF8_getc}
{$EXTERNALSYM UTF8_putc}
{$EXTERNALSYM ASN1_UTCTIME_new}
{$EXTERNALSYM ASN1_UTCTIME_free}
{$EXTERNALSYM d2i_ASN1_UTCTIME}
{$EXTERNALSYM i2d_ASN1_UTCTIME}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_new}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_free}
{$EXTERNALSYM d2i_ASN1_GENERALIZEDTIME}
{$EXTERNALSYM i2d_ASN1_GENERALIZEDTIME}
{$EXTERNALSYM ASN1_TIME_new}
{$EXTERNALSYM ASN1_TIME_free}
{$EXTERNALSYM d2i_ASN1_TIME}
{$EXTERNALSYM i2d_ASN1_TIME}
{$EXTERNALSYM ASN1_TIME_set}
{$EXTERNALSYM ASN1_TIME_adj}
{$EXTERNALSYM ASN1_TIME_check}
{$EXTERNALSYM ASN1_TIME_to_generalizedtime}
{$EXTERNALSYM ASN1_TIME_set_string}
{$EXTERNALSYM ASN1_TIME_set_string_X509}
{$EXTERNALSYM ASN1_TIME_to_tm}
{$EXTERNALSYM ASN1_TIME_normalize}
{$EXTERNALSYM ASN1_TIME_cmp_time_t}
{$EXTERNALSYM ASN1_TIME_compare}
{$EXTERNALSYM i2a_ASN1_INTEGER}
{$EXTERNALSYM a2i_ASN1_INTEGER}
{$EXTERNALSYM i2a_ASN1_ENUMERATED}
{$EXTERNALSYM a2i_ASN1_ENUMERATED}
{$EXTERNALSYM i2a_ASN1_OBJECT}
{$EXTERNALSYM a2i_ASN1_STRING}
{$EXTERNALSYM i2a_ASN1_STRING}
{$EXTERNALSYM i2t_ASN1_OBJECT}
{$EXTERNALSYM a2d_ASN1_OBJECT}
{$EXTERNALSYM ASN1_OBJECT_create}
{$EXTERNALSYM ASN1_INTEGER_get_int64}
{$EXTERNALSYM ASN1_INTEGER_set_int64}
{$EXTERNALSYM ASN1_INTEGER_get_uint64}
{$EXTERNALSYM ASN1_INTEGER_set_uint64}
{$EXTERNALSYM ASN1_INTEGER_set}
{$EXTERNALSYM ASN1_INTEGER_get}
{$EXTERNALSYM BN_to_ASN1_INTEGER}
{$EXTERNALSYM ASN1_INTEGER_to_BN}
{$EXTERNALSYM ASN1_ENUMERATED_get_int64}
{$EXTERNALSYM ASN1_ENUMERATED_set_int64}
{$EXTERNALSYM ASN1_ENUMERATED_set}
{$EXTERNALSYM ASN1_ENUMERATED_get}
{$EXTERNALSYM BN_to_ASN1_ENUMERATED}
{$EXTERNALSYM ASN1_ENUMERATED_to_BN}
{$EXTERNALSYM ASN1_PRINTABLE_type}
{$EXTERNALSYM ASN1_tag2bit}
{$EXTERNALSYM ASN1_get_object}
{$EXTERNALSYM ASN1_check_infinite_end}
{$EXTERNALSYM ASN1_const_check_infinite_end}
{$EXTERNALSYM ASN1_put_object}
{$EXTERNALSYM ASN1_put_eoc}
{$EXTERNALSYM ASN1_object_size}
{$EXTERNALSYM ASN1_item_dup}
{$EXTERNALSYM ASN1_STRING_to_UTF8}
{$EXTERNALSYM ASN1_d2i_bio}
{$EXTERNALSYM ASN1_item_d2i_bio}
{$EXTERNALSYM ASN1_i2d_bio}
{$EXTERNALSYM ASN1_item_i2d_bio}
{$EXTERNALSYM ASN1_UTCTIME_print}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_print}
{$EXTERNALSYM ASN1_TIME_print}
{$EXTERNALSYM ASN1_STRING_print}
{$EXTERNALSYM ASN1_STRING_print_ex}
{$EXTERNALSYM ASN1_buf_print}
{$EXTERNALSYM ASN1_bn_print}
{$EXTERNALSYM ASN1_parse}
{$EXTERNALSYM ASN1_parse_dump}
{$EXTERNALSYM ASN1_tag2str}
{$EXTERNALSYM ASN1_UNIVERSALSTRING_to_string}
{$EXTERNALSYM ASN1_TYPE_set_octetstring}
{$EXTERNALSYM ASN1_TYPE_get_octetstring}
{$EXTERNALSYM ASN1_TYPE_set_int_octetstring}
{$EXTERNALSYM ASN1_TYPE_get_int_octetstring}
{$EXTERNALSYM ASN1_item_unpack}
{$EXTERNALSYM ASN1_item_pack}
{$EXTERNALSYM ASN1_STRING_set_default_mask}
{$EXTERNALSYM ASN1_STRING_set_default_mask_asc}
{$EXTERNALSYM ASN1_STRING_get_default_mask}
{$EXTERNALSYM ASN1_mbstring_copy}
{$EXTERNALSYM ASN1_mbstring_ncopy}
{$EXTERNALSYM ASN1_STRING_set_by_NID}
{$EXTERNALSYM ASN1_STRING_TABLE_get}
{$EXTERNALSYM ASN1_STRING_TABLE_add}
{$EXTERNALSYM ASN1_STRING_TABLE_cleanup}
{$EXTERNALSYM ASN1_item_new}
{$EXTERNALSYM ASN1_item_free}
{$EXTERNALSYM ASN1_item_d2i}
{$EXTERNALSYM ASN1_item_i2d}
{$EXTERNALSYM ASN1_item_ndef_i2d}
{$EXTERNALSYM ASN1_add_oid_module}
{$EXTERNALSYM ASN1_add_stable_module}
{$EXTERNALSYM ASN1_generate_nconf}
{$EXTERNALSYM ASN1_generate_v3}
{$EXTERNALSYM ASN1_str2mask}
{$EXTERNALSYM ASN1_item_print}
{$EXTERNALSYM ASN1_PCTX_new}
{$EXTERNALSYM ASN1_PCTX_free}
{$EXTERNALSYM ASN1_PCTX_get_flags}
{$EXTERNALSYM ASN1_PCTX_set_flags}
{$EXTERNALSYM ASN1_PCTX_get_nm_flags}
{$EXTERNALSYM ASN1_PCTX_set_nm_flags}
{$EXTERNALSYM ASN1_PCTX_get_cert_flags}
{$EXTERNALSYM ASN1_PCTX_set_cert_flags}
{$EXTERNALSYM ASN1_PCTX_get_oid_flags}
{$EXTERNALSYM ASN1_PCTX_set_oid_flags}
{$EXTERNALSYM ASN1_PCTX_get_str_flags}
{$EXTERNALSYM ASN1_PCTX_set_str_flags}
{$EXTERNALSYM ASN1_SCTX_free}
{$EXTERNALSYM ASN1_SCTX_get_item}
{$EXTERNALSYM ASN1_SCTX_get_template}
{$EXTERNALSYM ASN1_SCTX_get_flags}
{$EXTERNALSYM ASN1_SCTX_set_app_data}
{$EXTERNALSYM ASN1_SCTX_get_app_data}
{$EXTERNALSYM BIO_f_asn1}
{$EXTERNALSYM BIO_new_NDEF}
{$EXTERNALSYM i2d_ASN1_bio_stream}
{$EXTERNALSYM PEM_write_bio_ASN1_stream}
{$EXTERNALSYM SMIME_read_ASN1}
{$EXTERNALSYM SMIME_crlf_copy}
{$EXTERNALSYM SMIME_text}
{$EXTERNALSYM ASN1_ITEM_lookup}
{$EXTERNALSYM ASN1_ITEM_get}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ASN1_TYPE_get(const a: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_TYPE_set(a: PASN1_TYPE; type_: TOpenSSL_C_INT; value: Pointer); cdecl; external CLibCrypto;
function ASN1_TYPE_set1(a: PASN1_TYPE; type_: TOpenSSL_C_INT; const value: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_cmp(const a: PASN1_TYPE; const b: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_pack_sequence(const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl; external CLibCrypto;
function ASN1_TYPE_unpack_sequence(const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl; external CLibCrypto;
function ASN1_OBJECT_new: PASN1_OBJECT; cdecl; external CLibCrypto;
procedure ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl; external CLibCrypto;
function i2d_ASN1_OBJECT(const a: PASN1_OBJECT; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ASN1_OBJECT(a: PPASN1_OBJECT; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_OBJECT; cdecl; external CLibCrypto;
function ASN1_STRING_new: PASN1_STRING; cdecl; external CLibCrypto;
procedure ASN1_STRING_free(a: PASN1_STRING); cdecl; external CLibCrypto;
procedure ASN1_STRING_clear_free(a: PASN1_STRING); cdecl; external CLibCrypto;
function ASN1_STRING_copy(dst: PASN1_STRING; const str: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_dup(const a: PASN1_STRING): PASN1_STRING; cdecl; external CLibCrypto;
function ASN1_STRING_type_new(type_: TOpenSSL_C_INT): PASN1_STRING; cdecl; external CLibCrypto;
function ASN1_STRING_cmp(const a: PASN1_STRING; const b: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_set(str: PASN1_STRING; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function ASN1_STRING_length(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_STRING_length_set(x: PASN1_STRING; n: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function ASN1_STRING_type(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_get0_data(const x: PASN1_STRING): PByte; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PByte; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TOpenSSL_C_INT; value: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_get_bit(const a: PASN1_BIT_STRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_check(const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_name_print(out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_num_asc(const name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; const name: PAnsiChar; value: TOpenSSL_C_INT; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_new: PASN1_INTEGER; cdecl; external CLibCrypto;
procedure ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl; external CLibCrypto;
function d2i_ASN1_INTEGER(a: PPASN1_INTEGER; const in_: PPByte; len: TOpenSSL_C_Long): PASN1_INTEGER; cdecl; external CLibCrypto;
function i2d_ASN1_INTEGER(a: PASN1_INTEGER; out_: PPByte): TOpenSSL_C_Int; cdecl; external CLibCrypto;
function d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_INTEGER; cdecl; external CLibCrypto;
function ASN1_INTEGER_dup(const x: PASN1_INTEGER): PASN1_INTEGER; cdecl; external CLibCrypto;
function ASN1_INTEGER_cmp(const x: PASN1_INTEGER; const y: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_check(const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): PASN1_UTCTIME; cdecl; external CLibCrypto;
function ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl; external CLibCrypto;
function ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_cmp_time_t(const s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_check(const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_set_string(s: pASN1_GENERALIZEDTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_diff(pday: POpenSSL_C_INT; psec: POpenSSL_C_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_dup(const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_cmp(const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; const data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl; external CLibCrypto;
procedure ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl; external CLibCrypto;
function d2i_ASN1_OCTET_STRING(val_out : PPASN1_OCTET_STRING; der_in : PPAnsiChar; length : TOpenSSL_C_LONG): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function i2d_ASN1_OCTET_STRING(val_in : PASN1_OCTET_STRING; der_out : PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UTF8_getc(const str: PByte; len: TOpenSSL_C_INT; val: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UTF8_putc(str: PAnsiChar; len: TOpenSSL_C_INT; value: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl; external CLibCrypto;
procedure ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl; external CLibCrypto;
function d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl; external CLibCrypto;
function i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
procedure ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl; external CLibCrypto;
function d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_new: PASN1_TIME; cdecl; external CLibCrypto;
procedure ASN1_TIME_free(a: PASN1_TIME); cdecl; external CLibCrypto;
function d2i_ASN1_TIME(a: PPASN1_TIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_TIME; cdecl; external CLibCrypto;
function i2d_ASN1_TIME(a: PASN1_TIME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_set(s: PASN1_TIME; t: TOpenSSL_C_TIMET): PASN1_TIME; cdecl; external CLibCrypto;
function ASN1_TIME_adj(s: PASN1_TIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_TIME; cdecl; external CLibCrypto;
function ASN1_TIME_check(const t: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_to_generalizedtime(const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function ASN1_TIME_set_string(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_set_string_X509(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_to_tm(const s: PASN1_TIME; tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_normalize(s: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_cmp_time_t(const s: PASN1_TIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_compare(const a: PASN1_TIME; const b: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_INTEGER(bp: PBIO; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_ENUMERATED(bp: PBIO; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_OBJECT(bp: PBIO; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_STRING(bp: PBIO; const a: PASN1_STRING; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2t_ASN1_OBJECT(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2d_ASN1_OBJECT(out_: PByte; olen: TOpenSSL_C_INT; const buf: PAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OBJECT_create(nid: TOpenSSL_C_INT; data: PByte; len: TOpenSSL_C_INT; const sn: PAnsiChar; const ln: PAnsiChar): PASN1_OBJECT; cdecl; external CLibCrypto;
function ASN1_INTEGER_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_get_uint64(pr: POpenSSL_C_UInt64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TOpenSSL_C_UInt64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_set(a: PASN1_INTEGER; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_get(const a: PASN1_INTEGER): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BN_to_ASN1_INTEGER(const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl; external CLibCrypto;
function ASN1_INTEGER_to_BN(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_get(const a: PASN1_ENUMERATED): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BN_to_ASN1_ENUMERATED(const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_to_BN(const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function ASN1_PRINTABLE_type(const s: PByte; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_tag2bit(tag: TOpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ASN1_get_object(const pp: PPByte; plength: POpenSSL_C_LONG; ptag: POpenSSL_C_INT; pclass: POpenSSL_C_INT; omax: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_check_infinite_end(p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_const_check_infinite_end(const p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_put_object(pp: PPByte; constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT; xclass: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function ASN1_put_eoc(pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_object_size(constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_dup(const it: PASN1_ITEM; x: Pointer): Pointer; cdecl; external CLibCrypto;
function ASN1_STRING_to_UTF8(out_: PPByte; const in_: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_d2i_bio(xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl; external CLibCrypto;
function ASN1_item_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl; external CLibCrypto;
function ASN1_i2d_bio(i2d: Pi2d_of_void; out_: PBIO; x: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_i2d_bio(const it: PASN1_ITEM; out_: PBIO; x: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_print(fp: PBIO; const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_print(fp: PBIO; const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_print(fp: PBIO; const a: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_print(bp: PBIO; const v: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_print_ex(out_: PBIO; const str: PASN1_STRING; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_buf_print(bp: PBIO; const buf: PByte; buflen: TOpenSSL_C_SIZET; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_bn_print(bp: PBIO; const number: PAnsiChar; const num: PBIGNUM; buf: PByte; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_parse(bp: PBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_parse_dump(bp: PPBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT; dump: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_tag2str(tag: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_get_octetstring(const a: PASN1_TYPE; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TOpenSSL_C_LONG; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_get_int_octetstring(const a: PASN1_TYPE; num: POpenSSL_C_LONG; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_unpack(const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl; external CLibCrypto;
function ASN1_item_pack(obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl; external CLibCrypto;
procedure ASN1_STRING_set_default_mask(mask: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_STRING_set_default_mask_asc(const p: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_get_default_mask: TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ASN1_mbstring_copy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_mbstring_ncopy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG; minsize: TOpenSSL_C_LONG; maxsize: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_set_by_NID(out_: PPASN1_STRING; const in_: PByte; inlen: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; nid: TOpenSSL_C_INT): PASN1_STRING; cdecl; external CLibCrypto;
function ASN1_STRING_TABLE_get(nid: TOpenSSL_C_INT): PASN1_STRING_TABLE; cdecl; external CLibCrypto;
function ASN1_STRING_TABLE_add(v1: TOpenSSL_C_INT; v2: TOpenSSL_C_LONG; v3: TOpenSSL_C_LONG; v4: TOpenSSL_C_ULONG; v5: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_STRING_TABLE_cleanup; cdecl; external CLibCrypto;
function ASN1_item_new(const it: PASN1_ITEM): PASN1_VALUE; cdecl; external CLibCrypto;
procedure ASN1_item_free(val: PASN1_VALUE; const it: PASN1_ITEM); cdecl; external CLibCrypto;
function ASN1_item_d2i(val: PPASN1_VALUE; const in_: PPByte; len: TOpenSSL_C_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl; external CLibCrypto;
function ASN1_item_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_ndef_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_add_oid_module; cdecl; external CLibCrypto;
procedure ASN1_add_stable_module; cdecl; external CLibCrypto;
function ASN1_generate_nconf(const str: PAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl; external CLibCrypto;
function ASN1_generate_v3(const str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl; external CLibCrypto;
function ASN1_str2mask(const str: PByte; pmask: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_print(out_: PBIO; ifld: PASN1_VALUE; indent: TOpenSSL_C_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_PCTX_new: PASN1_PCTX; cdecl; external CLibCrypto;
procedure ASN1_PCTX_free(p: PASN1_PCTX); cdecl; external CLibCrypto;
function ASN1_PCTX_get_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_nm_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_cert_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_oid_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_str_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
procedure ASN1_SCTX_free(p: PASN1_SCTX); cdecl; external CLibCrypto;
function ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl; external CLibCrypto;
function ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl; external CLibCrypto;
function ASN1_SCTX_get_flags(p: PASN1_SCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl; external CLibCrypto;
function ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl; external CLibCrypto;
function BIO_f_asn1: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_new_NDEF(out_: PBIO; val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl; external CLibCrypto;
function i2d_ASN1_bio_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_ASN1_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const hdr: PAnsiChar; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl; external CLibCrypto;
function SMIME_crlf_copy(in_: PBIO; out_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_text(in_: PBIO; out_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ITEM_lookup(const name: PAnsiChar): PASN1_ITEM; cdecl; external CLibCrypto;
function ASN1_ITEM_get(i: TOpenSSL_C_SIZET): PASN1_ITEM; cdecl; external CLibCrypto;

{$ELSE}
var
  ASN1_TYPE_get: function (const a: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TYPE_set: procedure (a: PASN1_TYPE; type_: TOpenSSL_C_INT; value: Pointer); cdecl = nil;
  ASN1_TYPE_set1: function (a: PASN1_TYPE; type_: TOpenSSL_C_INT; const value: Pointer): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TYPE_cmp: function (const a: PASN1_TYPE; const b: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TYPE_pack_sequence: function (const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl = nil;
  ASN1_TYPE_unpack_sequence: function (const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl = nil;
  ASN1_OBJECT_new: function : PASN1_OBJECT; cdecl = nil;
  ASN1_OBJECT_free: procedure (a: PASN1_OBJECT); cdecl = nil;
  i2d_ASN1_OBJECT: function (const a: PASN1_OBJECT; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_ASN1_OBJECT: function (a: PPASN1_OBJECT; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_OBJECT; cdecl = nil;
  ASN1_STRING_new: function : PASN1_STRING; cdecl = nil;
  ASN1_STRING_free: procedure (a: PASN1_STRING); cdecl = nil;
  ASN1_STRING_clear_free: procedure (a: PASN1_STRING); cdecl = nil;
  ASN1_STRING_copy: function (dst: PASN1_STRING; const str: PASN1_STRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_dup: function (const a: PASN1_STRING): PASN1_STRING; cdecl = nil;
  ASN1_STRING_type_new: function (type_: TOpenSSL_C_INT): PASN1_STRING; cdecl = nil;
  ASN1_STRING_cmp: function (const a: PASN1_STRING; const b: PASN1_STRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_set: function (str: PASN1_STRING; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_set0: procedure (str: PASN1_STRING; data: Pointer; len: TOpenSSL_C_INT); cdecl = nil;
  ASN1_STRING_length: function (const x: PASN1_STRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_length_set: procedure (x: PASN1_STRING; n: TOpenSSL_C_INT); cdecl = nil;
  ASN1_STRING_type: function (const x: PASN1_STRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_get0_data: function (const x: PASN1_STRING): PByte; cdecl = nil;
  ASN1_BIT_STRING_set: function (a: PASN1_BIT_STRING; d: PByte; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_BIT_STRING_set_bit: function (a: PASN1_BIT_STRING; n: TOpenSSL_C_INT; value: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_BIT_STRING_get_bit: function (const a: PASN1_BIT_STRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_BIT_STRING_check: function (const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_BIT_STRING_name_print: function (out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_BIT_STRING_num_asc: function (const name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_BIT_STRING_set_asc: function (bs: PASN1_BIT_STRING; const name: PAnsiChar; value: TOpenSSL_C_INT; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_INTEGER_new: function : PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_free: procedure (a: PASN1_INTEGER); cdecl = nil;
  d2i_ASN1_INTEGER: function (a: PPASN1_INTEGER; const in_: PPByte; len: TOpenSSL_C_Long): PASN1_INTEGER; cdecl = nil;
  i2d_ASN1_INTEGER: function (a: PASN1_INTEGER; out_: PPByte): TOpenSSL_C_Int; cdecl = nil;
  d2i_ASN1_UINTEGER: function (a: PPASN1_INTEGER; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_dup: function (const x: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_cmp: function (const x: PASN1_INTEGER; const y: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  ASN1_UTCTIME_check: function (const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_UTCTIME_set: function (s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): PASN1_UTCTIME; cdecl = nil;
  ASN1_UTCTIME_adj: function (s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl = nil;
  ASN1_UTCTIME_set_string: function (s: PASN1_UTCTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ASN1_UTCTIME_cmp_time_t: function (const s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_check: function (const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_set: function (s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET): PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_adj: function (s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_set_string: function (s: pASN1_GENERALIZEDTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_diff: function (pday: POpenSSL_C_INT; psec: POpenSSL_C_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_OCTET_STRING_dup: function (const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl = nil;
  ASN1_OCTET_STRING_cmp: function (const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_OCTET_STRING_set: function (str: PASN1_OCTET_STRING; const data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_OCTET_STRING_new: function : PASN1_OCTET_STRING; cdecl = nil;
  ASN1_OCTET_STRING_free: procedure (a: PASN1_OCTET_STRING); cdecl = nil;
  d2i_ASN1_OCTET_STRING: function (val_out : PPASN1_OCTET_STRING; der_in : PPAnsiChar; length : TOpenSSL_C_LONG): PASN1_OCTET_STRING; cdecl = nil;
  i2d_ASN1_OCTET_STRING: function (val_in : PASN1_OCTET_STRING; der_out : PPAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UTF8_getc: function (const str: PByte; len: TOpenSSL_C_INT; val: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  UTF8_putc: function (str: PAnsiChar; len: TOpenSSL_C_INT; value: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_UTCTIME_new: function : PASN1_UTCTIME; cdecl = nil;
  ASN1_UTCTIME_free: procedure (a: PASN1_UTCTIME); cdecl = nil;
  d2i_ASN1_UTCTIME: function (a: PPASN1_UTCTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl = nil;
  i2d_ASN1_UTCTIME: function (a: PASN1_UTCTIME; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_new: function : PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_free: procedure (a: PASN1_GENERALIZEDTIME); cdecl = nil;
  d2i_ASN1_GENERALIZEDTIME: function (a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl = nil;
  i2d_ASN1_GENERALIZEDTIME: function (a: PASN1_GENERALIZEDTIME; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_new: function : PASN1_TIME; cdecl = nil;
  ASN1_TIME_free: procedure (a: PASN1_TIME); cdecl = nil;
  d2i_ASN1_TIME: function (a: PPASN1_TIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_TIME; cdecl = nil;
  i2d_ASN1_TIME: function (a: PASN1_TIME; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_set: function (s: PASN1_TIME; t: TOpenSSL_C_TIMET): PASN1_TIME; cdecl = nil;
  ASN1_TIME_adj: function (s: PASN1_TIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_TIME; cdecl = nil;
  ASN1_TIME_check: function (const t: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_to_generalizedtime: function (const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_TIME_set_string: function (s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_set_string_X509: function (s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_to_tm: function (const s: PASN1_TIME; tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_normalize: function (s: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_cmp_time_t: function (const s: PASN1_TIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_compare: function (const a: PASN1_TIME; const b: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  i2a_ASN1_INTEGER: function (bp: PBIO; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  a2i_ASN1_INTEGER: function (bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  i2a_ASN1_ENUMERATED: function (bp: PBIO; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl = nil;
  a2i_ASN1_ENUMERATED: function (bp: PBIO; bs: PASN1_ENUMERATED; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  i2a_ASN1_OBJECT: function (bp: PBIO; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  a2i_ASN1_STRING: function (bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  i2a_ASN1_STRING: function (bp: PBIO; const a: PASN1_STRING; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  i2t_ASN1_OBJECT: function (buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  a2d_ASN1_OBJECT: function (out_: PByte; olen: TOpenSSL_C_INT; const buf: PAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_OBJECT_create: function (nid: TOpenSSL_C_INT; data: PByte; len: TOpenSSL_C_INT; const sn: PAnsiChar; const ln: PAnsiChar): PASN1_OBJECT; cdecl = nil;
  ASN1_INTEGER_get_int64: function (pr: POpenSSL_C_Int64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  ASN1_INTEGER_set_int64: function (a: PASN1_INTEGER; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl = nil;
  ASN1_INTEGER_get_uint64: function (pr: POpenSSL_C_UInt64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  ASN1_INTEGER_set_uint64: function (a: PASN1_INTEGER; r: TOpenSSL_C_UInt64): TOpenSSL_C_INT; cdecl = nil;
  ASN1_INTEGER_set: function (a: PASN1_INTEGER; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_INTEGER_get: function (const a: PASN1_INTEGER): TOpenSSL_C_LONG; cdecl = nil;
  BN_to_ASN1_INTEGER: function (const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_to_BN: function (const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl = nil;
  ASN1_ENUMERATED_get_int64: function (pr: POpenSSL_C_Int64; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl = nil;
  ASN1_ENUMERATED_set_int64: function (a: PASN1_ENUMERATED; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl = nil;
  ASN1_ENUMERATED_set: function (a: PASN1_ENUMERATED; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_ENUMERATED_get: function (const a: PASN1_ENUMERATED): TOpenSSL_C_LONG; cdecl = nil;
  BN_to_ASN1_ENUMERATED: function (const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl = nil;
  ASN1_ENUMERATED_to_BN: function (const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl = nil;
  ASN1_PRINTABLE_type: function (const s: PByte; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_tag2bit: function (tag: TOpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_get_object: function (const pp: PPByte; plength: POpenSSL_C_LONG; ptag: POpenSSL_C_INT; pclass: POpenSSL_C_INT; omax: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_check_infinite_end: function (p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_const_check_infinite_end: function (const p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_put_object: procedure (pp: PPByte; constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT; xclass: TOpenSSL_C_INT); cdecl = nil;
  ASN1_put_eoc: function (pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  ASN1_object_size: function (constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_dup: function (const it: PASN1_ITEM; x: Pointer): Pointer; cdecl = nil;
  ASN1_STRING_to_UTF8: function (out_: PPByte; const in_: PASN1_STRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_d2i_bio: function (xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl = nil;
  ASN1_item_d2i_bio: function (const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl = nil;
  ASN1_i2d_bio: function (i2d: Pi2d_of_void; out_: PBIO; x: PByte): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_i2d_bio: function (const it: PASN1_ITEM; out_: PBIO; x: Pointer): TOpenSSL_C_INT; cdecl = nil;
  ASN1_UTCTIME_print: function (fp: PBIO; const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_print: function (fp: PBIO; const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TIME_print: function (fp: PBIO; const a: PASN1_TIME): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_print: function (bp: PBIO; const v: PASN1_STRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_print_ex: function (out_: PBIO; const str: PASN1_STRING; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_buf_print: function (bp: PBIO; const buf: PByte; buflen: TOpenSSL_C_SIZET; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_bn_print: function (bp: PBIO; const number: PAnsiChar; const num: PBIGNUM; buf: PByte; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_parse: function (bp: PBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_parse_dump: function (bp: PPBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT; dump: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_tag2str: function (tag: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  ASN1_UNIVERSALSTRING_to_string: function (s: PASN1_UNIVERSALSTRING): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TYPE_set_octetstring: function (a: PASN1_TYPE; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TYPE_get_octetstring: function (const a: PASN1_TYPE; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TYPE_set_int_octetstring: function (a: PASN1_TYPE; num: TOpenSSL_C_LONG; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_TYPE_get_int_octetstring: function (const a: PASN1_TYPE; num: POpenSSL_C_LONG; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_unpack: function (const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl = nil;
  ASN1_item_pack: function (obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl = nil;
  ASN1_STRING_set_default_mask: procedure (mask: TOpenSSL_C_ULONG); cdecl = nil;
  ASN1_STRING_set_default_mask_asc: function (const p: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_get_default_mask: function : TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_mbstring_copy: function (out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_mbstring_ncopy: function (out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG; minsize: TOpenSSL_C_LONG; maxsize: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_set_by_NID: function (out_: PPASN1_STRING; const in_: PByte; inlen: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; nid: TOpenSSL_C_INT): PASN1_STRING; cdecl = nil;
  ASN1_STRING_TABLE_get: function (nid: TOpenSSL_C_INT): PASN1_STRING_TABLE; cdecl = nil;
  ASN1_STRING_TABLE_add: function (v1: TOpenSSL_C_INT; v2: TOpenSSL_C_LONG; v3: TOpenSSL_C_LONG; v4: TOpenSSL_C_ULONG; v5: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_STRING_TABLE_cleanup: procedure ; cdecl = nil;
  ASN1_item_new: function (const it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  ASN1_item_free: procedure (val: PASN1_VALUE; const it: PASN1_ITEM); cdecl = nil;
  ASN1_item_d2i: function (val: PPASN1_VALUE; const in_: PPByte; len: TOpenSSL_C_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  ASN1_item_i2d: function (val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_ndef_i2d: function (val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = nil;
  ASN1_add_oid_module: procedure ; cdecl = nil;
  ASN1_add_stable_module: procedure ; cdecl = nil;
  ASN1_generate_nconf: function (const str: PAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl = nil;
  ASN1_generate_v3: function (const str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl = nil;
  ASN1_str2mask: function (const str: PByte; pmask: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  ASN1_item_print: function (out_: PBIO; ifld: PASN1_VALUE; indent: TOpenSSL_C_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = nil;
  ASN1_PCTX_new: function : PASN1_PCTX; cdecl = nil;
  ASN1_PCTX_free: procedure (p: PASN1_PCTX); cdecl = nil;
  ASN1_PCTX_get_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_PCTX_set_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = nil;
  ASN1_PCTX_get_nm_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_PCTX_set_nm_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = nil;
  ASN1_PCTX_get_cert_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_PCTX_set_cert_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = nil;
  ASN1_PCTX_get_oid_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_PCTX_set_oid_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = nil;
  ASN1_PCTX_get_str_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_PCTX_set_str_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = nil;
  ASN1_SCTX_free: procedure (p: PASN1_SCTX); cdecl = nil;
  ASN1_SCTX_get_item: function (p: PASN1_SCTX): PASN1_ITEM; cdecl = nil;
  ASN1_SCTX_get_template: function (p: PASN1_SCTX): PASN1_TEMPLATE; cdecl = nil;
  ASN1_SCTX_get_flags: function (p: PASN1_SCTX): TOpenSSL_C_ULONG; cdecl = nil;
  ASN1_SCTX_set_app_data: procedure (p: PASN1_SCTX; data: Pointer); cdecl = nil;
  ASN1_SCTX_get_app_data: function (p: PASN1_SCTX): Pointer; cdecl = nil;
  BIO_f_asn1: function : PBIO_METHOD; cdecl = nil;
  BIO_new_NDEF: function (out_: PBIO; val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl = nil;
  i2d_ASN1_bio_stream: function (out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = nil;
  PEM_write_bio_ASN1_stream: function (out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const hdr: PAnsiChar; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = nil;
  SMIME_read_ASN1: function (bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  SMIME_crlf_copy: function (in_: PBIO; out_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  SMIME_text: function (in_: PBIO; out_: PBIO): TOpenSSL_C_INT; cdecl = nil;
  ASN1_ITEM_lookup: function (const name: PAnsiChar): PASN1_ITEM; cdecl = nil;
  ASN1_ITEM_get: function (i: TOpenSSL_C_SIZET): PASN1_ITEM; cdecl = nil;
{$ENDIF}
const
  ASN1_TYPE_pack_sequence_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TYPE_unpack_sequence_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_STRING_get0_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_set_string_X509_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_to_tm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_normalize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_cmp_time_t_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_compare_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_get_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_set_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_get_uint64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_set_uint64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ENUMERATED_get_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ENUMERATED_set_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_buf_print_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_add_stable_module_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_str2mask_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_item_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_template_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_set_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ITEM_lookup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ITEM_get_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function ERROR_ASN1_TYPE_get(const a: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_get');
end;

procedure ERROR_ASN1_TYPE_set(a: PASN1_TYPE; type_: TOpenSSL_C_INT; value: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set');
end;

function ERROR_ASN1_TYPE_set1(a: PASN1_TYPE; type_: TOpenSSL_C_INT; const value: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set1');
end;

function ERROR_ASN1_TYPE_cmp(const a: PASN1_TYPE; const b: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_cmp');
end;

function ERROR_ASN1_TYPE_pack_sequence(const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_pack_sequence');
end;

function ERROR_ASN1_TYPE_unpack_sequence(const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_unpack_sequence');
end;

function ERROR_ASN1_OBJECT_new: PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OBJECT_new');
end;

procedure ERROR_ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OBJECT_free');
end;

function ERROR_i2d_ASN1_OBJECT(const a: PASN1_OBJECT; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_OBJECT');
end;

function ERROR_d2i_ASN1_OBJECT(a: PPASN1_OBJECT; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_OBJECT');
end;

function ERROR_ASN1_STRING_new: PASN1_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_new');
end;

procedure ERROR_ASN1_STRING_free(a: PASN1_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_free');
end;

procedure ERROR_ASN1_STRING_clear_free(a: PASN1_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_clear_free');
end;

function ERROR_ASN1_STRING_copy(dst: PASN1_STRING; const str: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_copy');
end;

function ERROR_ASN1_STRING_dup(const a: PASN1_STRING): PASN1_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_dup');
end;

function ERROR_ASN1_STRING_type_new(type_: TOpenSSL_C_INT): PASN1_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_type_new');
end;

function ERROR_ASN1_STRING_cmp(const a: PASN1_STRING; const b: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_cmp');
end;

function ERROR_ASN1_STRING_set(str: PASN1_STRING; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set');
end;

procedure ERROR_ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set0');
end;

function ERROR_ASN1_STRING_length(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_length');
end;

procedure ERROR_ASN1_STRING_length_set(x: PASN1_STRING; n: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_length_set');
end;

function ERROR_ASN1_STRING_type(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_type');
end;

function ERROR_ASN1_STRING_get0_data(const x: PASN1_STRING): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_get0_data');
end;

function ERROR_ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PByte; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_set');
end;

function ERROR_ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TOpenSSL_C_INT; value: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_set_bit');
end;

function ERROR_ASN1_BIT_STRING_get_bit(const a: PASN1_BIT_STRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_get_bit');
end;

function ERROR_ASN1_BIT_STRING_check(const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_check');
end;

function ERROR_ASN1_BIT_STRING_name_print(out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_name_print');
end;

function ERROR_ASN1_BIT_STRING_num_asc(const name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_num_asc');
end;

function ERROR_ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; const name: PAnsiChar; value: TOpenSSL_C_INT; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_set_asc');
end;

function ERROR_ASN1_INTEGER_new: PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_new');
end;

procedure ERROR_ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_free');
end;

function ERROR_d2i_ASN1_INTEGER(a: PPASN1_INTEGER; const in_: PPByte; len: TOpenSSL_C_Long): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_INTEGER');
end;

function ERROR_i2d_ASN1_INTEGER(a: PASN1_INTEGER; out_: PPByte): TOpenSSL_C_Int; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_INTEGER');
end;

function ERROR_d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_UINTEGER');
end;

function ERROR_ASN1_INTEGER_dup(const x: PASN1_INTEGER): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_dup');
end;

function ERROR_ASN1_INTEGER_cmp(const x: PASN1_INTEGER; const y: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_cmp');
end;

function ERROR_ASN1_UTCTIME_check(const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_check');
end;

function ERROR_ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): PASN1_UTCTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_set');
end;

function ERROR_ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_adj');
end;

function ERROR_ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_set_string');
end;

function ERROR_ASN1_UTCTIME_cmp_time_t(const s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_cmp_time_t');
end;

function ERROR_ASN1_GENERALIZEDTIME_check(const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_check');
end;

function ERROR_ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET): PASN1_GENERALIZEDTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_set');
end;

function ERROR_ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_adj');
end;

function ERROR_ASN1_GENERALIZEDTIME_set_string(s: pASN1_GENERALIZEDTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_set_string');
end;

function ERROR_ASN1_TIME_diff(pday: POpenSSL_C_INT; psec: POpenSSL_C_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_diff');
end;

function ERROR_ASN1_OCTET_STRING_dup(const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_dup');
end;

function ERROR_ASN1_OCTET_STRING_cmp(const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_cmp');
end;

function ERROR_ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; const data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_set');
end;

function ERROR_ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_new');
end;

procedure ERROR_ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_free');
end;

function ERROR_d2i_ASN1_OCTET_STRING(val_out : PPASN1_OCTET_STRING; der_in : PPAnsiChar; length : TOpenSSL_C_LONG): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_OCTET_STRING');
end;

function ERROR_i2d_ASN1_OCTET_STRING(val_in : PASN1_OCTET_STRING; der_out : PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_OCTET_STRING');
end;

function ERROR_UTF8_getc(const str: PByte; len: TOpenSSL_C_INT; val: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UTF8_getc');
end;

function ERROR_UTF8_putc(str: PAnsiChar; len: TOpenSSL_C_INT; value: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UTF8_putc');
end;

function ERROR_ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_new');
end;

procedure ERROR_ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_free');
end;

function ERROR_d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_UTCTIME');
end;

function ERROR_i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_UTCTIME');
end;

function ERROR_ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_new');
end;

procedure ERROR_ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_free');
end;

function ERROR_d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_GENERALIZEDTIME');
end;

function ERROR_i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_GENERALIZEDTIME');
end;

function ERROR_ASN1_TIME_new: PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_new');
end;

procedure ERROR_ASN1_TIME_free(a: PASN1_TIME); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_free');
end;

function ERROR_d2i_ASN1_TIME(a: PPASN1_TIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_TIME');
end;

function ERROR_i2d_ASN1_TIME(a: PASN1_TIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_TIME');
end;

function ERROR_ASN1_TIME_set(s: PASN1_TIME; t: TOpenSSL_C_TIMET): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_set');
end;

function ERROR_ASN1_TIME_adj(s: PASN1_TIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_adj');
end;

function ERROR_ASN1_TIME_check(const t: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_check');
end;

function ERROR_ASN1_TIME_to_generalizedtime(const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_to_generalizedtime');
end;

function ERROR_ASN1_TIME_set_string(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_set_string');
end;

function ERROR_ASN1_TIME_set_string_X509(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_set_string_X509');
end;

function ERROR_ASN1_TIME_to_tm(const s: PASN1_TIME; tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_to_tm');
end;

function ERROR_ASN1_TIME_normalize(s: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_normalize');
end;

function ERROR_ASN1_TIME_cmp_time_t(const s: PASN1_TIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_cmp_time_t');
end;

function ERROR_ASN1_TIME_compare(const a: PASN1_TIME; const b: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_compare');
end;

function ERROR_i2a_ASN1_INTEGER(bp: PBIO; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_INTEGER');
end;

function ERROR_a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_ASN1_INTEGER');
end;

function ERROR_i2a_ASN1_ENUMERATED(bp: PBIO; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_ENUMERATED');
end;

function ERROR_a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_ASN1_ENUMERATED');
end;

function ERROR_i2a_ASN1_OBJECT(bp: PBIO; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_OBJECT');
end;

function ERROR_a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_ASN1_STRING');
end;

function ERROR_i2a_ASN1_STRING(bp: PBIO; const a: PASN1_STRING; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_STRING');
end;

function ERROR_i2t_ASN1_OBJECT(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2t_ASN1_OBJECT');
end;

function ERROR_a2d_ASN1_OBJECT(out_: PByte; olen: TOpenSSL_C_INT; const buf: PAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('a2d_ASN1_OBJECT');
end;

function ERROR_ASN1_OBJECT_create(nid: TOpenSSL_C_INT; data: PByte; len: TOpenSSL_C_INT; const sn: PAnsiChar; const ln: PAnsiChar): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OBJECT_create');
end;

function ERROR_ASN1_INTEGER_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_get_int64');
end;

function ERROR_ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_set_int64');
end;

function ERROR_ASN1_INTEGER_get_uint64(pr: POpenSSL_C_UInt64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_get_uint64');
end;

function ERROR_ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TOpenSSL_C_UInt64): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_set_uint64');
end;

function ERROR_ASN1_INTEGER_set(a: PASN1_INTEGER; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_set');
end;

function ERROR_ASN1_INTEGER_get(const a: PASN1_INTEGER): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_get');
end;

function ERROR_BN_to_ASN1_INTEGER(const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_to_ASN1_INTEGER');
end;

function ERROR_ASN1_INTEGER_to_BN(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_to_BN');
end;

function ERROR_ASN1_ENUMERATED_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_get_int64');
end;

function ERROR_ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_set_int64');
end;

function ERROR_ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_set');
end;

function ERROR_ASN1_ENUMERATED_get(const a: PASN1_ENUMERATED): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_get');
end;

function ERROR_BN_to_ASN1_ENUMERATED(const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_to_ASN1_ENUMERATED');
end;

function ERROR_ASN1_ENUMERATED_to_BN(const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_to_BN');
end;

function ERROR_ASN1_PRINTABLE_type(const s: PByte; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PRINTABLE_type');
end;

function ERROR_ASN1_tag2bit(tag: TOpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_tag2bit');
end;

function ERROR_ASN1_get_object(const pp: PPByte; plength: POpenSSL_C_LONG; ptag: POpenSSL_C_INT; pclass: POpenSSL_C_INT; omax: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_get_object');
end;

function ERROR_ASN1_check_infinite_end(p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_check_infinite_end');
end;

function ERROR_ASN1_const_check_infinite_end(const p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_const_check_infinite_end');
end;

procedure ERROR_ASN1_put_object(pp: PPByte; constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT; xclass: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_put_object');
end;

function ERROR_ASN1_put_eoc(pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_put_eoc');
end;

function ERROR_ASN1_object_size(constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_object_size');
end;

function ERROR_ASN1_item_dup(const it: PASN1_ITEM; x: Pointer): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_dup');
end;

function ERROR_ASN1_STRING_to_UTF8(out_: PPByte; const in_: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_to_UTF8');
end;

function ERROR_ASN1_d2i_bio(xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_d2i_bio');
end;

function ERROR_ASN1_item_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_d2i_bio');
end;

function ERROR_ASN1_i2d_bio(i2d: Pi2d_of_void; out_: PBIO; x: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_i2d_bio');
end;

function ERROR_ASN1_item_i2d_bio(const it: PASN1_ITEM; out_: PBIO; x: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_i2d_bio');
end;

function ERROR_ASN1_UTCTIME_print(fp: PBIO; const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_print');
end;

function ERROR_ASN1_GENERALIZEDTIME_print(fp: PBIO; const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_print');
end;

function ERROR_ASN1_TIME_print(fp: PBIO; const a: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_print');
end;

function ERROR_ASN1_STRING_print(bp: PBIO; const v: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_print');
end;

function ERROR_ASN1_STRING_print_ex(out_: PBIO; const str: PASN1_STRING; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_print_ex');
end;

function ERROR_ASN1_buf_print(bp: PBIO; const buf: PByte; buflen: TOpenSSL_C_SIZET; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_buf_print');
end;

function ERROR_ASN1_bn_print(bp: PBIO; const number: PAnsiChar; const num: PBIGNUM; buf: PByte; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_bn_print');
end;

function ERROR_ASN1_parse(bp: PBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_parse');
end;

function ERROR_ASN1_parse_dump(bp: PPBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT; dump: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_parse_dump');
end;

function ERROR_ASN1_tag2str(tag: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_tag2str');
end;

function ERROR_ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UNIVERSALSTRING_to_string');
end;

function ERROR_ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set_octetstring');
end;

function ERROR_ASN1_TYPE_get_octetstring(const a: PASN1_TYPE; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_get_octetstring');
end;

function ERROR_ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TOpenSSL_C_LONG; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set_int_octetstring');
end;

function ERROR_ASN1_TYPE_get_int_octetstring(const a: PASN1_TYPE; num: POpenSSL_C_LONG; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_get_int_octetstring');
end;

function ERROR_ASN1_item_unpack(const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_unpack');
end;

function ERROR_ASN1_item_pack(obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_pack');
end;

procedure ERROR_ASN1_STRING_set_default_mask(mask: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set_default_mask');
end;

function ERROR_ASN1_STRING_set_default_mask_asc(const p: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set_default_mask_asc');
end;

function ERROR_ASN1_STRING_get_default_mask: TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_get_default_mask');
end;

function ERROR_ASN1_mbstring_copy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_mbstring_copy');
end;

function ERROR_ASN1_mbstring_ncopy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG; minsize: TOpenSSL_C_LONG; maxsize: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_mbstring_ncopy');
end;

function ERROR_ASN1_STRING_set_by_NID(out_: PPASN1_STRING; const in_: PByte; inlen: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; nid: TOpenSSL_C_INT): PASN1_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set_by_NID');
end;

function ERROR_ASN1_STRING_TABLE_get(nid: TOpenSSL_C_INT): PASN1_STRING_TABLE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_TABLE_get');
end;

function ERROR_ASN1_STRING_TABLE_add(v1: TOpenSSL_C_INT; v2: TOpenSSL_C_LONG; v3: TOpenSSL_C_LONG; v4: TOpenSSL_C_ULONG; v5: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_TABLE_add');
end;

procedure ERROR_ASN1_STRING_TABLE_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_TABLE_cleanup');
end;

function ERROR_ASN1_item_new(const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_new');
end;

procedure ERROR_ASN1_item_free(val: PASN1_VALUE; const it: PASN1_ITEM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_free');
end;

function ERROR_ASN1_item_d2i(val: PPASN1_VALUE; const in_: PPByte; len: TOpenSSL_C_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_d2i');
end;

function ERROR_ASN1_item_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_i2d');
end;

function ERROR_ASN1_item_ndef_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_ndef_i2d');
end;

procedure ERROR_ASN1_add_oid_module; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_add_oid_module');
end;

procedure ERROR_ASN1_add_stable_module; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_add_stable_module');
end;

function ERROR_ASN1_generate_nconf(const str: PAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_generate_nconf');
end;

function ERROR_ASN1_generate_v3(const str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_generate_v3');
end;

function ERROR_ASN1_str2mask(const str: PByte; pmask: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_str2mask');
end;

function ERROR_ASN1_item_print(out_: PBIO; ifld: PASN1_VALUE; indent: TOpenSSL_C_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_print');
end;

function ERROR_ASN1_PCTX_new: PASN1_PCTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_new');
end;

procedure ERROR_ASN1_PCTX_free(p: PASN1_PCTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_free');
end;

function ERROR_ASN1_PCTX_get_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_flags');
end;

procedure ERROR_ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_flags');
end;

function ERROR_ASN1_PCTX_get_nm_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_nm_flags');
end;

procedure ERROR_ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_nm_flags');
end;

function ERROR_ASN1_PCTX_get_cert_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_cert_flags');
end;

procedure ERROR_ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_cert_flags');
end;

function ERROR_ASN1_PCTX_get_oid_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_oid_flags');
end;

procedure ERROR_ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_oid_flags');
end;

function ERROR_ASN1_PCTX_get_str_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_str_flags');
end;

procedure ERROR_ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_str_flags');
end;

procedure ERROR_ASN1_SCTX_free(p: PASN1_SCTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_free');
end;

function ERROR_ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_item');
end;

function ERROR_ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_template');
end;

function ERROR_ASN1_SCTX_get_flags(p: PASN1_SCTX): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_flags');
end;

procedure ERROR_ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_set_app_data');
end;

function ERROR_ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_app_data');
end;

function ERROR_BIO_f_asn1: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_asn1');
end;

function ERROR_BIO_new_NDEF(out_: PBIO; val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_NDEF');
end;

function ERROR_i2d_ASN1_bio_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_bio_stream');
end;

function ERROR_PEM_write_bio_ASN1_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const hdr: PAnsiChar; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ASN1_stream');
end;

function ERROR_SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_read_ASN1');
end;

function ERROR_SMIME_crlf_copy(in_: PBIO; out_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_crlf_copy');
end;

function ERROR_SMIME_text(in_: PBIO; out_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_text');
end;

function ERROR_ASN1_ITEM_lookup(const name: PAnsiChar): PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ITEM_lookup');
end;

function ERROR_ASN1_ITEM_get(i: TOpenSSL_C_SIZET): PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ITEM_get');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  ASN1_TYPE_get := LoadLibCryptoFunction('ASN1_TYPE_get');
  FuncLoadError := not assigned(ASN1_TYPE_get);
  if FuncLoadError then
  begin
    ASN1_TYPE_get :=  @ERROR_ASN1_TYPE_get;
  end;

  ASN1_TYPE_set := LoadLibCryptoFunction('ASN1_TYPE_set');
  FuncLoadError := not assigned(ASN1_TYPE_set);
  if FuncLoadError then
  begin
    ASN1_TYPE_set :=  @ERROR_ASN1_TYPE_set;
  end;

  ASN1_TYPE_set1 := LoadLibCryptoFunction('ASN1_TYPE_set1');
  FuncLoadError := not assigned(ASN1_TYPE_set1);
  if FuncLoadError then
  begin
    ASN1_TYPE_set1 :=  @ERROR_ASN1_TYPE_set1;
  end;

  ASN1_TYPE_cmp := LoadLibCryptoFunction('ASN1_TYPE_cmp');
  FuncLoadError := not assigned(ASN1_TYPE_cmp);
  if FuncLoadError then
  begin
    ASN1_TYPE_cmp :=  @ERROR_ASN1_TYPE_cmp;
  end;

  ASN1_TYPE_pack_sequence := LoadLibCryptoFunction('ASN1_TYPE_pack_sequence');
  FuncLoadError := not assigned(ASN1_TYPE_pack_sequence);
  if FuncLoadError then
  begin
    ASN1_TYPE_pack_sequence :=  @ERROR_ASN1_TYPE_pack_sequence;
  end;

  ASN1_TYPE_unpack_sequence := LoadLibCryptoFunction('ASN1_TYPE_unpack_sequence');
  FuncLoadError := not assigned(ASN1_TYPE_unpack_sequence);
  if FuncLoadError then
  begin
    ASN1_TYPE_unpack_sequence :=  @ERROR_ASN1_TYPE_unpack_sequence;
  end;

  ASN1_OBJECT_new := LoadLibCryptoFunction('ASN1_OBJECT_new');
  FuncLoadError := not assigned(ASN1_OBJECT_new);
  if FuncLoadError then
  begin
    ASN1_OBJECT_new :=  @ERROR_ASN1_OBJECT_new;
  end;

  ASN1_OBJECT_free := LoadLibCryptoFunction('ASN1_OBJECT_free');
  FuncLoadError := not assigned(ASN1_OBJECT_free);
  if FuncLoadError then
  begin
    ASN1_OBJECT_free :=  @ERROR_ASN1_OBJECT_free;
  end;

  i2d_ASN1_OBJECT := LoadLibCryptoFunction('i2d_ASN1_OBJECT');
  FuncLoadError := not assigned(i2d_ASN1_OBJECT);
  if FuncLoadError then
  begin
    i2d_ASN1_OBJECT :=  @ERROR_i2d_ASN1_OBJECT;
  end;

  d2i_ASN1_OBJECT := LoadLibCryptoFunction('d2i_ASN1_OBJECT');
  FuncLoadError := not assigned(d2i_ASN1_OBJECT);
  if FuncLoadError then
  begin
    d2i_ASN1_OBJECT :=  @ERROR_d2i_ASN1_OBJECT;
  end;

  ASN1_STRING_new := LoadLibCryptoFunction('ASN1_STRING_new');
  FuncLoadError := not assigned(ASN1_STRING_new);
  if FuncLoadError then
  begin
    ASN1_STRING_new :=  @ERROR_ASN1_STRING_new;
  end;

  ASN1_STRING_free := LoadLibCryptoFunction('ASN1_STRING_free');
  FuncLoadError := not assigned(ASN1_STRING_free);
  if FuncLoadError then
  begin
    ASN1_STRING_free :=  @ERROR_ASN1_STRING_free;
  end;

  ASN1_STRING_clear_free := LoadLibCryptoFunction('ASN1_STRING_clear_free');
  FuncLoadError := not assigned(ASN1_STRING_clear_free);
  if FuncLoadError then
  begin
    ASN1_STRING_clear_free :=  @ERROR_ASN1_STRING_clear_free;
  end;

  ASN1_STRING_copy := LoadLibCryptoFunction('ASN1_STRING_copy');
  FuncLoadError := not assigned(ASN1_STRING_copy);
  if FuncLoadError then
  begin
    ASN1_STRING_copy :=  @ERROR_ASN1_STRING_copy;
  end;

  ASN1_STRING_dup := LoadLibCryptoFunction('ASN1_STRING_dup');
  FuncLoadError := not assigned(ASN1_STRING_dup);
  if FuncLoadError then
  begin
    ASN1_STRING_dup :=  @ERROR_ASN1_STRING_dup;
  end;

  ASN1_STRING_type_new := LoadLibCryptoFunction('ASN1_STRING_type_new');
  FuncLoadError := not assigned(ASN1_STRING_type_new);
  if FuncLoadError then
  begin
    ASN1_STRING_type_new :=  @ERROR_ASN1_STRING_type_new;
  end;

  ASN1_STRING_cmp := LoadLibCryptoFunction('ASN1_STRING_cmp');
  FuncLoadError := not assigned(ASN1_STRING_cmp);
  if FuncLoadError then
  begin
    ASN1_STRING_cmp :=  @ERROR_ASN1_STRING_cmp;
  end;

  ASN1_STRING_set := LoadLibCryptoFunction('ASN1_STRING_set');
  FuncLoadError := not assigned(ASN1_STRING_set);
  if FuncLoadError then
  begin
    ASN1_STRING_set :=  @ERROR_ASN1_STRING_set;
  end;

  ASN1_STRING_set0 := LoadLibCryptoFunction('ASN1_STRING_set0');
  FuncLoadError := not assigned(ASN1_STRING_set0);
  if FuncLoadError then
  begin
    ASN1_STRING_set0 :=  @ERROR_ASN1_STRING_set0;
  end;

  ASN1_STRING_length := LoadLibCryptoFunction('ASN1_STRING_length');
  FuncLoadError := not assigned(ASN1_STRING_length);
  if FuncLoadError then
  begin
    ASN1_STRING_length :=  @ERROR_ASN1_STRING_length;
  end;

  ASN1_STRING_length_set := LoadLibCryptoFunction('ASN1_STRING_length_set');
  FuncLoadError := not assigned(ASN1_STRING_length_set);
  if FuncLoadError then
  begin
    ASN1_STRING_length_set :=  @ERROR_ASN1_STRING_length_set;
  end;

  ASN1_STRING_type := LoadLibCryptoFunction('ASN1_STRING_type');
  FuncLoadError := not assigned(ASN1_STRING_type);
  if FuncLoadError then
  begin
    ASN1_STRING_type :=  @ERROR_ASN1_STRING_type;
  end;

  ASN1_STRING_get0_data := LoadLibCryptoFunction('ASN1_STRING_get0_data');
  FuncLoadError := not assigned(ASN1_STRING_get0_data);
  if FuncLoadError then
  begin
    ASN1_STRING_get0_data :=  @ERROR_ASN1_STRING_get0_data;
  end;

  ASN1_BIT_STRING_set := LoadLibCryptoFunction('ASN1_BIT_STRING_set');
  FuncLoadError := not assigned(ASN1_BIT_STRING_set);
  if FuncLoadError then
  begin
    ASN1_BIT_STRING_set :=  @ERROR_ASN1_BIT_STRING_set;
  end;

  ASN1_BIT_STRING_set_bit := LoadLibCryptoFunction('ASN1_BIT_STRING_set_bit');
  FuncLoadError := not assigned(ASN1_BIT_STRING_set_bit);
  if FuncLoadError then
  begin
    ASN1_BIT_STRING_set_bit :=  @ERROR_ASN1_BIT_STRING_set_bit;
  end;

  ASN1_BIT_STRING_get_bit := LoadLibCryptoFunction('ASN1_BIT_STRING_get_bit');
  FuncLoadError := not assigned(ASN1_BIT_STRING_get_bit);
  if FuncLoadError then
  begin
    ASN1_BIT_STRING_get_bit :=  @ERROR_ASN1_BIT_STRING_get_bit;
  end;

  ASN1_BIT_STRING_check := LoadLibCryptoFunction('ASN1_BIT_STRING_check');
  FuncLoadError := not assigned(ASN1_BIT_STRING_check);
  if FuncLoadError then
  begin
    ASN1_BIT_STRING_check :=  @ERROR_ASN1_BIT_STRING_check;
  end;

  ASN1_BIT_STRING_name_print := LoadLibCryptoFunction('ASN1_BIT_STRING_name_print');
  FuncLoadError := not assigned(ASN1_BIT_STRING_name_print);
  if FuncLoadError then
  begin
    ASN1_BIT_STRING_name_print :=  @ERROR_ASN1_BIT_STRING_name_print;
  end;

  ASN1_BIT_STRING_num_asc := LoadLibCryptoFunction('ASN1_BIT_STRING_num_asc');
  FuncLoadError := not assigned(ASN1_BIT_STRING_num_asc);
  if FuncLoadError then
  begin
    ASN1_BIT_STRING_num_asc :=  @ERROR_ASN1_BIT_STRING_num_asc;
  end;

  ASN1_BIT_STRING_set_asc := LoadLibCryptoFunction('ASN1_BIT_STRING_set_asc');
  FuncLoadError := not assigned(ASN1_BIT_STRING_set_asc);
  if FuncLoadError then
  begin
    ASN1_BIT_STRING_set_asc :=  @ERROR_ASN1_BIT_STRING_set_asc;
  end;

  ASN1_INTEGER_new := LoadLibCryptoFunction('ASN1_INTEGER_new');
  FuncLoadError := not assigned(ASN1_INTEGER_new);
  if FuncLoadError then
  begin
    ASN1_INTEGER_new :=  @ERROR_ASN1_INTEGER_new;
  end;

  ASN1_INTEGER_free := LoadLibCryptoFunction('ASN1_INTEGER_free');
  FuncLoadError := not assigned(ASN1_INTEGER_free);
  if FuncLoadError then
  begin
    ASN1_INTEGER_free :=  @ERROR_ASN1_INTEGER_free;
  end;

  d2i_ASN1_INTEGER := LoadLibCryptoFunction('d2i_ASN1_INTEGER');
  FuncLoadError := not assigned(d2i_ASN1_INTEGER);
  if FuncLoadError then
  begin
    d2i_ASN1_INTEGER :=  @ERROR_d2i_ASN1_INTEGER;
  end;

  i2d_ASN1_INTEGER := LoadLibCryptoFunction('i2d_ASN1_INTEGER');
  FuncLoadError := not assigned(i2d_ASN1_INTEGER);
  if FuncLoadError then
  begin
    i2d_ASN1_INTEGER :=  @ERROR_i2d_ASN1_INTEGER;
  end;

  d2i_ASN1_UINTEGER := LoadLibCryptoFunction('d2i_ASN1_UINTEGER');
  FuncLoadError := not assigned(d2i_ASN1_UINTEGER);
  if FuncLoadError then
  begin
    d2i_ASN1_UINTEGER :=  @ERROR_d2i_ASN1_UINTEGER;
  end;

  ASN1_INTEGER_dup := LoadLibCryptoFunction('ASN1_INTEGER_dup');
  FuncLoadError := not assigned(ASN1_INTEGER_dup);
  if FuncLoadError then
  begin
    ASN1_INTEGER_dup :=  @ERROR_ASN1_INTEGER_dup;
  end;

  ASN1_INTEGER_cmp := LoadLibCryptoFunction('ASN1_INTEGER_cmp');
  FuncLoadError := not assigned(ASN1_INTEGER_cmp);
  if FuncLoadError then
  begin
    ASN1_INTEGER_cmp :=  @ERROR_ASN1_INTEGER_cmp;
  end;

  ASN1_UTCTIME_check := LoadLibCryptoFunction('ASN1_UTCTIME_check');
  FuncLoadError := not assigned(ASN1_UTCTIME_check);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_check :=  @ERROR_ASN1_UTCTIME_check;
  end;

  ASN1_UTCTIME_set := LoadLibCryptoFunction('ASN1_UTCTIME_set');
  FuncLoadError := not assigned(ASN1_UTCTIME_set);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_set :=  @ERROR_ASN1_UTCTIME_set;
  end;

  ASN1_UTCTIME_adj := LoadLibCryptoFunction('ASN1_UTCTIME_adj');
  FuncLoadError := not assigned(ASN1_UTCTIME_adj);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_adj :=  @ERROR_ASN1_UTCTIME_adj;
  end;

  ASN1_UTCTIME_set_string := LoadLibCryptoFunction('ASN1_UTCTIME_set_string');
  FuncLoadError := not assigned(ASN1_UTCTIME_set_string);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_set_string :=  @ERROR_ASN1_UTCTIME_set_string;
  end;

  ASN1_UTCTIME_cmp_time_t := LoadLibCryptoFunction('ASN1_UTCTIME_cmp_time_t');
  FuncLoadError := not assigned(ASN1_UTCTIME_cmp_time_t);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_cmp_time_t :=  @ERROR_ASN1_UTCTIME_cmp_time_t;
  end;

  ASN1_GENERALIZEDTIME_check := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_check');
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_check);
  if FuncLoadError then
  begin
    ASN1_GENERALIZEDTIME_check :=  @ERROR_ASN1_GENERALIZEDTIME_check;
  end;

  ASN1_GENERALIZEDTIME_set := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_set');
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_set);
  if FuncLoadError then
  begin
    ASN1_GENERALIZEDTIME_set :=  @ERROR_ASN1_GENERALIZEDTIME_set;
  end;

  ASN1_GENERALIZEDTIME_adj := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_adj');
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_adj);
  if FuncLoadError then
  begin
    ASN1_GENERALIZEDTIME_adj :=  @ERROR_ASN1_GENERALIZEDTIME_adj;
  end;

  ASN1_GENERALIZEDTIME_set_string := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_set_string');
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_set_string);
  if FuncLoadError then
  begin
    ASN1_GENERALIZEDTIME_set_string :=  @ERROR_ASN1_GENERALIZEDTIME_set_string;
  end;

  ASN1_TIME_diff := LoadLibCryptoFunction('ASN1_TIME_diff');
  FuncLoadError := not assigned(ASN1_TIME_diff);
  if FuncLoadError then
  begin
    ASN1_TIME_diff :=  @ERROR_ASN1_TIME_diff;
  end;

  ASN1_OCTET_STRING_dup := LoadLibCryptoFunction('ASN1_OCTET_STRING_dup');
  FuncLoadError := not assigned(ASN1_OCTET_STRING_dup);
  if FuncLoadError then
  begin
    ASN1_OCTET_STRING_dup :=  @ERROR_ASN1_OCTET_STRING_dup;
  end;

  ASN1_OCTET_STRING_cmp := LoadLibCryptoFunction('ASN1_OCTET_STRING_cmp');
  FuncLoadError := not assigned(ASN1_OCTET_STRING_cmp);
  if FuncLoadError then
  begin
    ASN1_OCTET_STRING_cmp :=  @ERROR_ASN1_OCTET_STRING_cmp;
  end;

  ASN1_OCTET_STRING_set := LoadLibCryptoFunction('ASN1_OCTET_STRING_set');
  FuncLoadError := not assigned(ASN1_OCTET_STRING_set);
  if FuncLoadError then
  begin
    ASN1_OCTET_STRING_set :=  @ERROR_ASN1_OCTET_STRING_set;
  end;

  ASN1_OCTET_STRING_new := LoadLibCryptoFunction('ASN1_OCTET_STRING_new');
  FuncLoadError := not assigned(ASN1_OCTET_STRING_new);
  if FuncLoadError then
  begin
    ASN1_OCTET_STRING_new :=  @ERROR_ASN1_OCTET_STRING_new;
  end;

  ASN1_OCTET_STRING_free := LoadLibCryptoFunction('ASN1_OCTET_STRING_free');
  FuncLoadError := not assigned(ASN1_OCTET_STRING_free);
  if FuncLoadError then
  begin
    ASN1_OCTET_STRING_free :=  @ERROR_ASN1_OCTET_STRING_free;
  end;

  d2i_ASN1_OCTET_STRING := LoadLibCryptoFunction('d2i_ASN1_OCTET_STRING');
  FuncLoadError := not assigned(d2i_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    d2i_ASN1_OCTET_STRING :=  @ERROR_d2i_ASN1_OCTET_STRING;
  end;

  i2d_ASN1_OCTET_STRING := LoadLibCryptoFunction('i2d_ASN1_OCTET_STRING');
  FuncLoadError := not assigned(i2d_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    i2d_ASN1_OCTET_STRING :=  @ERROR_i2d_ASN1_OCTET_STRING;
  end;

  UTF8_getc := LoadLibCryptoFunction('UTF8_getc');
  FuncLoadError := not assigned(UTF8_getc);
  if FuncLoadError then
  begin
    UTF8_getc :=  @ERROR_UTF8_getc;
  end;

  UTF8_putc := LoadLibCryptoFunction('UTF8_putc');
  FuncLoadError := not assigned(UTF8_putc);
  if FuncLoadError then
  begin
    UTF8_putc :=  @ERROR_UTF8_putc;
  end;

  ASN1_UTCTIME_new := LoadLibCryptoFunction('ASN1_UTCTIME_new');
  FuncLoadError := not assigned(ASN1_UTCTIME_new);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_new :=  @ERROR_ASN1_UTCTIME_new;
  end;

  ASN1_UTCTIME_free := LoadLibCryptoFunction('ASN1_UTCTIME_free');
  FuncLoadError := not assigned(ASN1_UTCTIME_free);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_free :=  @ERROR_ASN1_UTCTIME_free;
  end;

  d2i_ASN1_UTCTIME := LoadLibCryptoFunction('d2i_ASN1_UTCTIME');
  FuncLoadError := not assigned(d2i_ASN1_UTCTIME);
  if FuncLoadError then
  begin
    d2i_ASN1_UTCTIME :=  @ERROR_d2i_ASN1_UTCTIME;
  end;

  i2d_ASN1_UTCTIME := LoadLibCryptoFunction('i2d_ASN1_UTCTIME');
  FuncLoadError := not assigned(i2d_ASN1_UTCTIME);
  if FuncLoadError then
  begin
    i2d_ASN1_UTCTIME :=  @ERROR_i2d_ASN1_UTCTIME;
  end;

  ASN1_GENERALIZEDTIME_new := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_new');
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_new);
  if FuncLoadError then
  begin
    ASN1_GENERALIZEDTIME_new :=  @ERROR_ASN1_GENERALIZEDTIME_new;
  end;

  ASN1_GENERALIZEDTIME_free := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_free');
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_free);
  if FuncLoadError then
  begin
    ASN1_GENERALIZEDTIME_free :=  @ERROR_ASN1_GENERALIZEDTIME_free;
  end;

  d2i_ASN1_GENERALIZEDTIME := LoadLibCryptoFunction('d2i_ASN1_GENERALIZEDTIME');
  FuncLoadError := not assigned(d2i_ASN1_GENERALIZEDTIME);
  if FuncLoadError then
  begin
    d2i_ASN1_GENERALIZEDTIME :=  @ERROR_d2i_ASN1_GENERALIZEDTIME;
  end;

  i2d_ASN1_GENERALIZEDTIME := LoadLibCryptoFunction('i2d_ASN1_GENERALIZEDTIME');
  FuncLoadError := not assigned(i2d_ASN1_GENERALIZEDTIME);
  if FuncLoadError then
  begin
    i2d_ASN1_GENERALIZEDTIME :=  @ERROR_i2d_ASN1_GENERALIZEDTIME;
  end;

  ASN1_TIME_new := LoadLibCryptoFunction('ASN1_TIME_new');
  FuncLoadError := not assigned(ASN1_TIME_new);
  if FuncLoadError then
  begin
    ASN1_TIME_new :=  @ERROR_ASN1_TIME_new;
  end;

  ASN1_TIME_free := LoadLibCryptoFunction('ASN1_TIME_free');
  FuncLoadError := not assigned(ASN1_TIME_free);
  if FuncLoadError then
  begin
    ASN1_TIME_free :=  @ERROR_ASN1_TIME_free;
  end;

  d2i_ASN1_TIME := LoadLibCryptoFunction('d2i_ASN1_TIME');
  FuncLoadError := not assigned(d2i_ASN1_TIME);
  if FuncLoadError then
  begin
    d2i_ASN1_TIME :=  @ERROR_d2i_ASN1_TIME;
  end;

  i2d_ASN1_TIME := LoadLibCryptoFunction('i2d_ASN1_TIME');
  FuncLoadError := not assigned(i2d_ASN1_TIME);
  if FuncLoadError then
  begin
    i2d_ASN1_TIME :=  @ERROR_i2d_ASN1_TIME;
  end;

  ASN1_TIME_set := LoadLibCryptoFunction('ASN1_TIME_set');
  FuncLoadError := not assigned(ASN1_TIME_set);
  if FuncLoadError then
  begin
    ASN1_TIME_set :=  @ERROR_ASN1_TIME_set;
  end;

  ASN1_TIME_adj := LoadLibCryptoFunction('ASN1_TIME_adj');
  FuncLoadError := not assigned(ASN1_TIME_adj);
  if FuncLoadError then
  begin
    ASN1_TIME_adj :=  @ERROR_ASN1_TIME_adj;
  end;

  ASN1_TIME_check := LoadLibCryptoFunction('ASN1_TIME_check');
  FuncLoadError := not assigned(ASN1_TIME_check);
  if FuncLoadError then
  begin
    ASN1_TIME_check :=  @ERROR_ASN1_TIME_check;
  end;

  ASN1_TIME_to_generalizedtime := LoadLibCryptoFunction('ASN1_TIME_to_generalizedtime');
  FuncLoadError := not assigned(ASN1_TIME_to_generalizedtime);
  if FuncLoadError then
  begin
    ASN1_TIME_to_generalizedtime :=  @ERROR_ASN1_TIME_to_generalizedtime;
  end;

  ASN1_TIME_set_string := LoadLibCryptoFunction('ASN1_TIME_set_string');
  FuncLoadError := not assigned(ASN1_TIME_set_string);
  if FuncLoadError then
  begin
    ASN1_TIME_set_string :=  @ERROR_ASN1_TIME_set_string;
  end;

  ASN1_TIME_set_string_X509 := LoadLibCryptoFunction('ASN1_TIME_set_string_X509');
  FuncLoadError := not assigned(ASN1_TIME_set_string_X509);
  if FuncLoadError then
  begin
    ASN1_TIME_set_string_X509 :=  @ERROR_ASN1_TIME_set_string_X509;
  end;

  ASN1_TIME_to_tm := LoadLibCryptoFunction('ASN1_TIME_to_tm');
  FuncLoadError := not assigned(ASN1_TIME_to_tm);
  if FuncLoadError then
  begin
    ASN1_TIME_to_tm :=  @ERROR_ASN1_TIME_to_tm;
  end;

  ASN1_TIME_normalize := LoadLibCryptoFunction('ASN1_TIME_normalize');
  FuncLoadError := not assigned(ASN1_TIME_normalize);
  if FuncLoadError then
  begin
    ASN1_TIME_normalize :=  @ERROR_ASN1_TIME_normalize;
  end;

  ASN1_TIME_cmp_time_t := LoadLibCryptoFunction('ASN1_TIME_cmp_time_t');
  FuncLoadError := not assigned(ASN1_TIME_cmp_time_t);
  if FuncLoadError then
  begin
    ASN1_TIME_cmp_time_t :=  @ERROR_ASN1_TIME_cmp_time_t;
  end;

  ASN1_TIME_compare := LoadLibCryptoFunction('ASN1_TIME_compare');
  FuncLoadError := not assigned(ASN1_TIME_compare);
  if FuncLoadError then
  begin
    ASN1_TIME_compare :=  @ERROR_ASN1_TIME_compare;
  end;

  i2a_ASN1_INTEGER := LoadLibCryptoFunction('i2a_ASN1_INTEGER');
  FuncLoadError := not assigned(i2a_ASN1_INTEGER);
  if FuncLoadError then
  begin
    i2a_ASN1_INTEGER :=  @ERROR_i2a_ASN1_INTEGER;
  end;

  a2i_ASN1_INTEGER := LoadLibCryptoFunction('a2i_ASN1_INTEGER');
  FuncLoadError := not assigned(a2i_ASN1_INTEGER);
  if FuncLoadError then
  begin
    a2i_ASN1_INTEGER :=  @ERROR_a2i_ASN1_INTEGER;
  end;

  i2a_ASN1_ENUMERATED := LoadLibCryptoFunction('i2a_ASN1_ENUMERATED');
  FuncLoadError := not assigned(i2a_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    i2a_ASN1_ENUMERATED :=  @ERROR_i2a_ASN1_ENUMERATED;
  end;

  a2i_ASN1_ENUMERATED := LoadLibCryptoFunction('a2i_ASN1_ENUMERATED');
  FuncLoadError := not assigned(a2i_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    a2i_ASN1_ENUMERATED :=  @ERROR_a2i_ASN1_ENUMERATED;
  end;

  i2a_ASN1_OBJECT := LoadLibCryptoFunction('i2a_ASN1_OBJECT');
  FuncLoadError := not assigned(i2a_ASN1_OBJECT);
  if FuncLoadError then
  begin
    i2a_ASN1_OBJECT :=  @ERROR_i2a_ASN1_OBJECT;
  end;

  a2i_ASN1_STRING := LoadLibCryptoFunction('a2i_ASN1_STRING');
  FuncLoadError := not assigned(a2i_ASN1_STRING);
  if FuncLoadError then
  begin
    a2i_ASN1_STRING :=  @ERROR_a2i_ASN1_STRING;
  end;

  i2a_ASN1_STRING := LoadLibCryptoFunction('i2a_ASN1_STRING');
  FuncLoadError := not assigned(i2a_ASN1_STRING);
  if FuncLoadError then
  begin
    i2a_ASN1_STRING :=  @ERROR_i2a_ASN1_STRING;
  end;

  i2t_ASN1_OBJECT := LoadLibCryptoFunction('i2t_ASN1_OBJECT');
  FuncLoadError := not assigned(i2t_ASN1_OBJECT);
  if FuncLoadError then
  begin
    i2t_ASN1_OBJECT :=  @ERROR_i2t_ASN1_OBJECT;
  end;

  a2d_ASN1_OBJECT := LoadLibCryptoFunction('a2d_ASN1_OBJECT');
  FuncLoadError := not assigned(a2d_ASN1_OBJECT);
  if FuncLoadError then
  begin
    a2d_ASN1_OBJECT :=  @ERROR_a2d_ASN1_OBJECT;
  end;

  ASN1_OBJECT_create := LoadLibCryptoFunction('ASN1_OBJECT_create');
  FuncLoadError := not assigned(ASN1_OBJECT_create);
  if FuncLoadError then
  begin
    ASN1_OBJECT_create :=  @ERROR_ASN1_OBJECT_create;
  end;

  ASN1_INTEGER_get_int64 := LoadLibCryptoFunction('ASN1_INTEGER_get_int64');
  FuncLoadError := not assigned(ASN1_INTEGER_get_int64);
  if FuncLoadError then
  begin
    ASN1_INTEGER_get_int64 :=  @ERROR_ASN1_INTEGER_get_int64;
  end;

  ASN1_INTEGER_set_int64 := LoadLibCryptoFunction('ASN1_INTEGER_set_int64');
  FuncLoadError := not assigned(ASN1_INTEGER_set_int64);
  if FuncLoadError then
  begin
    ASN1_INTEGER_set_int64 :=  @ERROR_ASN1_INTEGER_set_int64;
  end;

  ASN1_INTEGER_get_uint64 := LoadLibCryptoFunction('ASN1_INTEGER_get_uint64');
  FuncLoadError := not assigned(ASN1_INTEGER_get_uint64);
  if FuncLoadError then
  begin
    ASN1_INTEGER_get_uint64 :=  @ERROR_ASN1_INTEGER_get_uint64;
  end;

  ASN1_INTEGER_set_uint64 := LoadLibCryptoFunction('ASN1_INTEGER_set_uint64');
  FuncLoadError := not assigned(ASN1_INTEGER_set_uint64);
  if FuncLoadError then
  begin
    ASN1_INTEGER_set_uint64 :=  @ERROR_ASN1_INTEGER_set_uint64;
  end;

  ASN1_INTEGER_set := LoadLibCryptoFunction('ASN1_INTEGER_set');
  FuncLoadError := not assigned(ASN1_INTEGER_set);
  if FuncLoadError then
  begin
    ASN1_INTEGER_set :=  @ERROR_ASN1_INTEGER_set;
  end;

  ASN1_INTEGER_get := LoadLibCryptoFunction('ASN1_INTEGER_get');
  FuncLoadError := not assigned(ASN1_INTEGER_get);
  if FuncLoadError then
  begin
    ASN1_INTEGER_get :=  @ERROR_ASN1_INTEGER_get;
  end;

  BN_to_ASN1_INTEGER := LoadLibCryptoFunction('BN_to_ASN1_INTEGER');
  FuncLoadError := not assigned(BN_to_ASN1_INTEGER);
  if FuncLoadError then
  begin
    BN_to_ASN1_INTEGER :=  @ERROR_BN_to_ASN1_INTEGER;
  end;

  ASN1_INTEGER_to_BN := LoadLibCryptoFunction('ASN1_INTEGER_to_BN');
  FuncLoadError := not assigned(ASN1_INTEGER_to_BN);
  if FuncLoadError then
  begin
    ASN1_INTEGER_to_BN :=  @ERROR_ASN1_INTEGER_to_BN;
  end;

  ASN1_ENUMERATED_get_int64 := LoadLibCryptoFunction('ASN1_ENUMERATED_get_int64');
  FuncLoadError := not assigned(ASN1_ENUMERATED_get_int64);
  if FuncLoadError then
  begin
    ASN1_ENUMERATED_get_int64 :=  @ERROR_ASN1_ENUMERATED_get_int64;
  end;

  ASN1_ENUMERATED_set_int64 := LoadLibCryptoFunction('ASN1_ENUMERATED_set_int64');
  FuncLoadError := not assigned(ASN1_ENUMERATED_set_int64);
  if FuncLoadError then
  begin
    ASN1_ENUMERATED_set_int64 :=  @ERROR_ASN1_ENUMERATED_set_int64;
  end;

  ASN1_ENUMERATED_set := LoadLibCryptoFunction('ASN1_ENUMERATED_set');
  FuncLoadError := not assigned(ASN1_ENUMERATED_set);
  if FuncLoadError then
  begin
    ASN1_ENUMERATED_set :=  @ERROR_ASN1_ENUMERATED_set;
  end;

  ASN1_ENUMERATED_get := LoadLibCryptoFunction('ASN1_ENUMERATED_get');
  FuncLoadError := not assigned(ASN1_ENUMERATED_get);
  if FuncLoadError then
  begin
    ASN1_ENUMERATED_get :=  @ERROR_ASN1_ENUMERATED_get;
  end;

  BN_to_ASN1_ENUMERATED := LoadLibCryptoFunction('BN_to_ASN1_ENUMERATED');
  FuncLoadError := not assigned(BN_to_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    BN_to_ASN1_ENUMERATED :=  @ERROR_BN_to_ASN1_ENUMERATED;
  end;

  ASN1_ENUMERATED_to_BN := LoadLibCryptoFunction('ASN1_ENUMERATED_to_BN');
  FuncLoadError := not assigned(ASN1_ENUMERATED_to_BN);
  if FuncLoadError then
  begin
    ASN1_ENUMERATED_to_BN :=  @ERROR_ASN1_ENUMERATED_to_BN;
  end;

  ASN1_PRINTABLE_type := LoadLibCryptoFunction('ASN1_PRINTABLE_type');
  FuncLoadError := not assigned(ASN1_PRINTABLE_type);
  if FuncLoadError then
  begin
    ASN1_PRINTABLE_type :=  @ERROR_ASN1_PRINTABLE_type;
  end;

  ASN1_tag2bit := LoadLibCryptoFunction('ASN1_tag2bit');
  FuncLoadError := not assigned(ASN1_tag2bit);
  if FuncLoadError then
  begin
    ASN1_tag2bit :=  @ERROR_ASN1_tag2bit;
  end;

  ASN1_get_object := LoadLibCryptoFunction('ASN1_get_object');
  FuncLoadError := not assigned(ASN1_get_object);
  if FuncLoadError then
  begin
    ASN1_get_object :=  @ERROR_ASN1_get_object;
  end;

  ASN1_check_infinite_end := LoadLibCryptoFunction('ASN1_check_infinite_end');
  FuncLoadError := not assigned(ASN1_check_infinite_end);
  if FuncLoadError then
  begin
    ASN1_check_infinite_end :=  @ERROR_ASN1_check_infinite_end;
  end;

  ASN1_const_check_infinite_end := LoadLibCryptoFunction('ASN1_const_check_infinite_end');
  FuncLoadError := not assigned(ASN1_const_check_infinite_end);
  if FuncLoadError then
  begin
    ASN1_const_check_infinite_end :=  @ERROR_ASN1_const_check_infinite_end;
  end;

  ASN1_put_object := LoadLibCryptoFunction('ASN1_put_object');
  FuncLoadError := not assigned(ASN1_put_object);
  if FuncLoadError then
  begin
    ASN1_put_object :=  @ERROR_ASN1_put_object;
  end;

  ASN1_put_eoc := LoadLibCryptoFunction('ASN1_put_eoc');
  FuncLoadError := not assigned(ASN1_put_eoc);
  if FuncLoadError then
  begin
    ASN1_put_eoc :=  @ERROR_ASN1_put_eoc;
  end;

  ASN1_object_size := LoadLibCryptoFunction('ASN1_object_size');
  FuncLoadError := not assigned(ASN1_object_size);
  if FuncLoadError then
  begin
    ASN1_object_size :=  @ERROR_ASN1_object_size;
  end;

  ASN1_item_dup := LoadLibCryptoFunction('ASN1_item_dup');
  FuncLoadError := not assigned(ASN1_item_dup);
  if FuncLoadError then
  begin
    ASN1_item_dup :=  @ERROR_ASN1_item_dup;
  end;

  ASN1_STRING_to_UTF8 := LoadLibCryptoFunction('ASN1_STRING_to_UTF8');
  FuncLoadError := not assigned(ASN1_STRING_to_UTF8);
  if FuncLoadError then
  begin
    ASN1_STRING_to_UTF8 :=  @ERROR_ASN1_STRING_to_UTF8;
  end;

  ASN1_d2i_bio := LoadLibCryptoFunction('ASN1_d2i_bio');
  FuncLoadError := not assigned(ASN1_d2i_bio);
  if FuncLoadError then
  begin
    ASN1_d2i_bio :=  @ERROR_ASN1_d2i_bio;
  end;

  ASN1_item_d2i_bio := LoadLibCryptoFunction('ASN1_item_d2i_bio');
  FuncLoadError := not assigned(ASN1_item_d2i_bio);
  if FuncLoadError then
  begin
    ASN1_item_d2i_bio :=  @ERROR_ASN1_item_d2i_bio;
  end;

  ASN1_i2d_bio := LoadLibCryptoFunction('ASN1_i2d_bio');
  FuncLoadError := not assigned(ASN1_i2d_bio);
  if FuncLoadError then
  begin
    ASN1_i2d_bio :=  @ERROR_ASN1_i2d_bio;
  end;

  ASN1_item_i2d_bio := LoadLibCryptoFunction('ASN1_item_i2d_bio');
  FuncLoadError := not assigned(ASN1_item_i2d_bio);
  if FuncLoadError then
  begin
    ASN1_item_i2d_bio :=  @ERROR_ASN1_item_i2d_bio;
  end;

  ASN1_UTCTIME_print := LoadLibCryptoFunction('ASN1_UTCTIME_print');
  FuncLoadError := not assigned(ASN1_UTCTIME_print);
  if FuncLoadError then
  begin
    ASN1_UTCTIME_print :=  @ERROR_ASN1_UTCTIME_print;
  end;

  ASN1_GENERALIZEDTIME_print := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_print');
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_print);
  if FuncLoadError then
  begin
    ASN1_GENERALIZEDTIME_print :=  @ERROR_ASN1_GENERALIZEDTIME_print;
  end;

  ASN1_TIME_print := LoadLibCryptoFunction('ASN1_TIME_print');
  FuncLoadError := not assigned(ASN1_TIME_print);
  if FuncLoadError then
  begin
    ASN1_TIME_print :=  @ERROR_ASN1_TIME_print;
  end;

  ASN1_STRING_print := LoadLibCryptoFunction('ASN1_STRING_print');
  FuncLoadError := not assigned(ASN1_STRING_print);
  if FuncLoadError then
  begin
    ASN1_STRING_print :=  @ERROR_ASN1_STRING_print;
  end;

  ASN1_STRING_print_ex := LoadLibCryptoFunction('ASN1_STRING_print_ex');
  FuncLoadError := not assigned(ASN1_STRING_print_ex);
  if FuncLoadError then
  begin
    ASN1_STRING_print_ex :=  @ERROR_ASN1_STRING_print_ex;
  end;

  ASN1_buf_print := LoadLibCryptoFunction('ASN1_buf_print');
  FuncLoadError := not assigned(ASN1_buf_print);
  if FuncLoadError then
  begin
    ASN1_buf_print :=  @ERROR_ASN1_buf_print;
  end;

  ASN1_bn_print := LoadLibCryptoFunction('ASN1_bn_print');
  FuncLoadError := not assigned(ASN1_bn_print);
  if FuncLoadError then
  begin
    ASN1_bn_print :=  @ERROR_ASN1_bn_print;
  end;

  ASN1_parse := LoadLibCryptoFunction('ASN1_parse');
  FuncLoadError := not assigned(ASN1_parse);
  if FuncLoadError then
  begin
    ASN1_parse :=  @ERROR_ASN1_parse;
  end;

  ASN1_parse_dump := LoadLibCryptoFunction('ASN1_parse_dump');
  FuncLoadError := not assigned(ASN1_parse_dump);
  if FuncLoadError then
  begin
    ASN1_parse_dump :=  @ERROR_ASN1_parse_dump;
  end;

  ASN1_tag2str := LoadLibCryptoFunction('ASN1_tag2str');
  FuncLoadError := not assigned(ASN1_tag2str);
  if FuncLoadError then
  begin
    ASN1_tag2str :=  @ERROR_ASN1_tag2str;
  end;

  ASN1_UNIVERSALSTRING_to_string := LoadLibCryptoFunction('ASN1_UNIVERSALSTRING_to_string');
  FuncLoadError := not assigned(ASN1_UNIVERSALSTRING_to_string);
  if FuncLoadError then
  begin
    ASN1_UNIVERSALSTRING_to_string :=  @ERROR_ASN1_UNIVERSALSTRING_to_string;
  end;

  ASN1_TYPE_set_octetstring := LoadLibCryptoFunction('ASN1_TYPE_set_octetstring');
  FuncLoadError := not assigned(ASN1_TYPE_set_octetstring);
  if FuncLoadError then
  begin
    ASN1_TYPE_set_octetstring :=  @ERROR_ASN1_TYPE_set_octetstring;
  end;

  ASN1_TYPE_get_octetstring := LoadLibCryptoFunction('ASN1_TYPE_get_octetstring');
  FuncLoadError := not assigned(ASN1_TYPE_get_octetstring);
  if FuncLoadError then
  begin
    ASN1_TYPE_get_octetstring :=  @ERROR_ASN1_TYPE_get_octetstring;
  end;

  ASN1_TYPE_set_int_octetstring := LoadLibCryptoFunction('ASN1_TYPE_set_int_octetstring');
  FuncLoadError := not assigned(ASN1_TYPE_set_int_octetstring);
  if FuncLoadError then
  begin
    ASN1_TYPE_set_int_octetstring :=  @ERROR_ASN1_TYPE_set_int_octetstring;
  end;

  ASN1_TYPE_get_int_octetstring := LoadLibCryptoFunction('ASN1_TYPE_get_int_octetstring');
  FuncLoadError := not assigned(ASN1_TYPE_get_int_octetstring);
  if FuncLoadError then
  begin
    ASN1_TYPE_get_int_octetstring :=  @ERROR_ASN1_TYPE_get_int_octetstring;
  end;

  ASN1_item_unpack := LoadLibCryptoFunction('ASN1_item_unpack');
  FuncLoadError := not assigned(ASN1_item_unpack);
  if FuncLoadError then
  begin
    ASN1_item_unpack :=  @ERROR_ASN1_item_unpack;
  end;

  ASN1_item_pack := LoadLibCryptoFunction('ASN1_item_pack');
  FuncLoadError := not assigned(ASN1_item_pack);
  if FuncLoadError then
  begin
    ASN1_item_pack :=  @ERROR_ASN1_item_pack;
  end;

  ASN1_STRING_set_default_mask := LoadLibCryptoFunction('ASN1_STRING_set_default_mask');
  FuncLoadError := not assigned(ASN1_STRING_set_default_mask);
  if FuncLoadError then
  begin
    ASN1_STRING_set_default_mask :=  @ERROR_ASN1_STRING_set_default_mask;
  end;

  ASN1_STRING_set_default_mask_asc := LoadLibCryptoFunction('ASN1_STRING_set_default_mask_asc');
  FuncLoadError := not assigned(ASN1_STRING_set_default_mask_asc);
  if FuncLoadError then
  begin
    ASN1_STRING_set_default_mask_asc :=  @ERROR_ASN1_STRING_set_default_mask_asc;
  end;

  ASN1_STRING_get_default_mask := LoadLibCryptoFunction('ASN1_STRING_get_default_mask');
  FuncLoadError := not assigned(ASN1_STRING_get_default_mask);
  if FuncLoadError then
  begin
    ASN1_STRING_get_default_mask :=  @ERROR_ASN1_STRING_get_default_mask;
  end;

  ASN1_mbstring_copy := LoadLibCryptoFunction('ASN1_mbstring_copy');
  FuncLoadError := not assigned(ASN1_mbstring_copy);
  if FuncLoadError then
  begin
    ASN1_mbstring_copy :=  @ERROR_ASN1_mbstring_copy;
  end;

  ASN1_mbstring_ncopy := LoadLibCryptoFunction('ASN1_mbstring_ncopy');
  FuncLoadError := not assigned(ASN1_mbstring_ncopy);
  if FuncLoadError then
  begin
    ASN1_mbstring_ncopy :=  @ERROR_ASN1_mbstring_ncopy;
  end;

  ASN1_STRING_set_by_NID := LoadLibCryptoFunction('ASN1_STRING_set_by_NID');
  FuncLoadError := not assigned(ASN1_STRING_set_by_NID);
  if FuncLoadError then
  begin
    ASN1_STRING_set_by_NID :=  @ERROR_ASN1_STRING_set_by_NID;
  end;

  ASN1_STRING_TABLE_get := LoadLibCryptoFunction('ASN1_STRING_TABLE_get');
  FuncLoadError := not assigned(ASN1_STRING_TABLE_get);
  if FuncLoadError then
  begin
    ASN1_STRING_TABLE_get :=  @ERROR_ASN1_STRING_TABLE_get;
  end;

  ASN1_STRING_TABLE_add := LoadLibCryptoFunction('ASN1_STRING_TABLE_add');
  FuncLoadError := not assigned(ASN1_STRING_TABLE_add);
  if FuncLoadError then
  begin
    ASN1_STRING_TABLE_add :=  @ERROR_ASN1_STRING_TABLE_add;
  end;

  ASN1_STRING_TABLE_cleanup := LoadLibCryptoFunction('ASN1_STRING_TABLE_cleanup');
  FuncLoadError := not assigned(ASN1_STRING_TABLE_cleanup);
  if FuncLoadError then
  begin
    ASN1_STRING_TABLE_cleanup :=  @ERROR_ASN1_STRING_TABLE_cleanup;
  end;

  ASN1_item_new := LoadLibCryptoFunction('ASN1_item_new');
  FuncLoadError := not assigned(ASN1_item_new);
  if FuncLoadError then
  begin
    ASN1_item_new :=  @ERROR_ASN1_item_new;
  end;

  ASN1_item_free := LoadLibCryptoFunction('ASN1_item_free');
  FuncLoadError := not assigned(ASN1_item_free);
  if FuncLoadError then
  begin
    ASN1_item_free :=  @ERROR_ASN1_item_free;
  end;

  ASN1_item_d2i := LoadLibCryptoFunction('ASN1_item_d2i');
  FuncLoadError := not assigned(ASN1_item_d2i);
  if FuncLoadError then
  begin
    ASN1_item_d2i :=  @ERROR_ASN1_item_d2i;
  end;

  ASN1_item_i2d := LoadLibCryptoFunction('ASN1_item_i2d');
  FuncLoadError := not assigned(ASN1_item_i2d);
  if FuncLoadError then
  begin
    ASN1_item_i2d :=  @ERROR_ASN1_item_i2d;
  end;

  ASN1_item_ndef_i2d := LoadLibCryptoFunction('ASN1_item_ndef_i2d');
  FuncLoadError := not assigned(ASN1_item_ndef_i2d);
  if FuncLoadError then
  begin
    ASN1_item_ndef_i2d :=  @ERROR_ASN1_item_ndef_i2d;
  end;

  ASN1_add_oid_module := LoadLibCryptoFunction('ASN1_add_oid_module');
  FuncLoadError := not assigned(ASN1_add_oid_module);
  if FuncLoadError then
  begin
    ASN1_add_oid_module :=  @ERROR_ASN1_add_oid_module;
  end;

  ASN1_add_stable_module := LoadLibCryptoFunction('ASN1_add_stable_module');
  FuncLoadError := not assigned(ASN1_add_stable_module);
  if FuncLoadError then
  begin
    ASN1_add_stable_module :=  @ERROR_ASN1_add_stable_module;
  end;

  ASN1_generate_nconf := LoadLibCryptoFunction('ASN1_generate_nconf');
  FuncLoadError := not assigned(ASN1_generate_nconf);
  if FuncLoadError then
  begin
    ASN1_generate_nconf :=  @ERROR_ASN1_generate_nconf;
  end;

  ASN1_generate_v3 := LoadLibCryptoFunction('ASN1_generate_v3');
  FuncLoadError := not assigned(ASN1_generate_v3);
  if FuncLoadError then
  begin
    ASN1_generate_v3 :=  @ERROR_ASN1_generate_v3;
  end;

  ASN1_str2mask := LoadLibCryptoFunction('ASN1_str2mask');
  FuncLoadError := not assigned(ASN1_str2mask);
  if FuncLoadError then
  begin
    ASN1_str2mask :=  @ERROR_ASN1_str2mask;
  end;

  ASN1_item_print := LoadLibCryptoFunction('ASN1_item_print');
  FuncLoadError := not assigned(ASN1_item_print);
  if FuncLoadError then
  begin
    ASN1_item_print :=  @ERROR_ASN1_item_print;
  end;

  ASN1_PCTX_new := LoadLibCryptoFunction('ASN1_PCTX_new');
  FuncLoadError := not assigned(ASN1_PCTX_new);
  if FuncLoadError then
  begin
    ASN1_PCTX_new :=  @ERROR_ASN1_PCTX_new;
  end;

  ASN1_PCTX_free := LoadLibCryptoFunction('ASN1_PCTX_free');
  FuncLoadError := not assigned(ASN1_PCTX_free);
  if FuncLoadError then
  begin
    ASN1_PCTX_free :=  @ERROR_ASN1_PCTX_free;
  end;

  ASN1_PCTX_get_flags := LoadLibCryptoFunction('ASN1_PCTX_get_flags');
  FuncLoadError := not assigned(ASN1_PCTX_get_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_get_flags :=  @ERROR_ASN1_PCTX_get_flags;
  end;

  ASN1_PCTX_set_flags := LoadLibCryptoFunction('ASN1_PCTX_set_flags');
  FuncLoadError := not assigned(ASN1_PCTX_set_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_set_flags :=  @ERROR_ASN1_PCTX_set_flags;
  end;

  ASN1_PCTX_get_nm_flags := LoadLibCryptoFunction('ASN1_PCTX_get_nm_flags');
  FuncLoadError := not assigned(ASN1_PCTX_get_nm_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_get_nm_flags :=  @ERROR_ASN1_PCTX_get_nm_flags;
  end;

  ASN1_PCTX_set_nm_flags := LoadLibCryptoFunction('ASN1_PCTX_set_nm_flags');
  FuncLoadError := not assigned(ASN1_PCTX_set_nm_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_set_nm_flags :=  @ERROR_ASN1_PCTX_set_nm_flags;
  end;

  ASN1_PCTX_get_cert_flags := LoadLibCryptoFunction('ASN1_PCTX_get_cert_flags');
  FuncLoadError := not assigned(ASN1_PCTX_get_cert_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_get_cert_flags :=  @ERROR_ASN1_PCTX_get_cert_flags;
  end;

  ASN1_PCTX_set_cert_flags := LoadLibCryptoFunction('ASN1_PCTX_set_cert_flags');
  FuncLoadError := not assigned(ASN1_PCTX_set_cert_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_set_cert_flags :=  @ERROR_ASN1_PCTX_set_cert_flags;
  end;

  ASN1_PCTX_get_oid_flags := LoadLibCryptoFunction('ASN1_PCTX_get_oid_flags');
  FuncLoadError := not assigned(ASN1_PCTX_get_oid_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_get_oid_flags :=  @ERROR_ASN1_PCTX_get_oid_flags;
  end;

  ASN1_PCTX_set_oid_flags := LoadLibCryptoFunction('ASN1_PCTX_set_oid_flags');
  FuncLoadError := not assigned(ASN1_PCTX_set_oid_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_set_oid_flags :=  @ERROR_ASN1_PCTX_set_oid_flags;
  end;

  ASN1_PCTX_get_str_flags := LoadLibCryptoFunction('ASN1_PCTX_get_str_flags');
  FuncLoadError := not assigned(ASN1_PCTX_get_str_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_get_str_flags :=  @ERROR_ASN1_PCTX_get_str_flags;
  end;

  ASN1_PCTX_set_str_flags := LoadLibCryptoFunction('ASN1_PCTX_set_str_flags');
  FuncLoadError := not assigned(ASN1_PCTX_set_str_flags);
  if FuncLoadError then
  begin
    ASN1_PCTX_set_str_flags :=  @ERROR_ASN1_PCTX_set_str_flags;
  end;

  ASN1_SCTX_free := LoadLibCryptoFunction('ASN1_SCTX_free');
  FuncLoadError := not assigned(ASN1_SCTX_free);
  if FuncLoadError then
  begin
    ASN1_SCTX_free :=  @ERROR_ASN1_SCTX_free;
  end;

  ASN1_SCTX_get_item := LoadLibCryptoFunction('ASN1_SCTX_get_item');
  FuncLoadError := not assigned(ASN1_SCTX_get_item);
  if FuncLoadError then
  begin
    ASN1_SCTX_get_item :=  @ERROR_ASN1_SCTX_get_item;
  end;

  ASN1_SCTX_get_template := LoadLibCryptoFunction('ASN1_SCTX_get_template');
  FuncLoadError := not assigned(ASN1_SCTX_get_template);
  if FuncLoadError then
  begin
    ASN1_SCTX_get_template :=  @ERROR_ASN1_SCTX_get_template;
  end;

  ASN1_SCTX_get_flags := LoadLibCryptoFunction('ASN1_SCTX_get_flags');
  FuncLoadError := not assigned(ASN1_SCTX_get_flags);
  if FuncLoadError then
  begin
    ASN1_SCTX_get_flags :=  @ERROR_ASN1_SCTX_get_flags;
  end;

  ASN1_SCTX_set_app_data := LoadLibCryptoFunction('ASN1_SCTX_set_app_data');
  FuncLoadError := not assigned(ASN1_SCTX_set_app_data);
  if FuncLoadError then
  begin
    ASN1_SCTX_set_app_data :=  @ERROR_ASN1_SCTX_set_app_data;
  end;

  ASN1_SCTX_get_app_data := LoadLibCryptoFunction('ASN1_SCTX_get_app_data');
  FuncLoadError := not assigned(ASN1_SCTX_get_app_data);
  if FuncLoadError then
  begin
    ASN1_SCTX_get_app_data :=  @ERROR_ASN1_SCTX_get_app_data;
  end;

  BIO_f_asn1 := LoadLibCryptoFunction('BIO_f_asn1');
  FuncLoadError := not assigned(BIO_f_asn1);
  if FuncLoadError then
  begin
    BIO_f_asn1 :=  @ERROR_BIO_f_asn1;
  end;

  BIO_new_NDEF := LoadLibCryptoFunction('BIO_new_NDEF');
  FuncLoadError := not assigned(BIO_new_NDEF);
  if FuncLoadError then
  begin
    BIO_new_NDEF :=  @ERROR_BIO_new_NDEF;
  end;

  i2d_ASN1_bio_stream := LoadLibCryptoFunction('i2d_ASN1_bio_stream');
  FuncLoadError := not assigned(i2d_ASN1_bio_stream);
  if FuncLoadError then
  begin
    i2d_ASN1_bio_stream :=  @ERROR_i2d_ASN1_bio_stream;
  end;

  PEM_write_bio_ASN1_stream := LoadLibCryptoFunction('PEM_write_bio_ASN1_stream');
  FuncLoadError := not assigned(PEM_write_bio_ASN1_stream);
  if FuncLoadError then
  begin
    PEM_write_bio_ASN1_stream :=  @ERROR_PEM_write_bio_ASN1_stream;
  end;

  SMIME_read_ASN1 := LoadLibCryptoFunction('SMIME_read_ASN1');
  FuncLoadError := not assigned(SMIME_read_ASN1);
  if FuncLoadError then
  begin
    SMIME_read_ASN1 :=  @ERROR_SMIME_read_ASN1;
  end;

  SMIME_crlf_copy := LoadLibCryptoFunction('SMIME_crlf_copy');
  FuncLoadError := not assigned(SMIME_crlf_copy);
  if FuncLoadError then
  begin
    SMIME_crlf_copy :=  @ERROR_SMIME_crlf_copy;
  end;

  SMIME_text := LoadLibCryptoFunction('SMIME_text');
  FuncLoadError := not assigned(SMIME_text);
  if FuncLoadError then
  begin
    SMIME_text :=  @ERROR_SMIME_text;
  end;

  ASN1_ITEM_lookup := LoadLibCryptoFunction('ASN1_ITEM_lookup');
  FuncLoadError := not assigned(ASN1_ITEM_lookup);
  if FuncLoadError then
  begin
    ASN1_ITEM_lookup :=  @ERROR_ASN1_ITEM_lookup;
  end;

  ASN1_ITEM_get := LoadLibCryptoFunction('ASN1_ITEM_get');
  FuncLoadError := not assigned(ASN1_ITEM_get);
  if FuncLoadError then
  begin
    ASN1_ITEM_get :=  @ERROR_ASN1_ITEM_get;
  end;

end;

procedure UnLoad;
begin
  ASN1_TYPE_get := nil;
  ASN1_TYPE_set := nil;
  ASN1_TYPE_set1 := nil;
  ASN1_TYPE_cmp := nil;
  ASN1_TYPE_pack_sequence := nil;
  ASN1_TYPE_unpack_sequence := nil;
  ASN1_OBJECT_new := nil;
  ASN1_OBJECT_free := nil;
  i2d_ASN1_OBJECT := nil;
  d2i_ASN1_OBJECT := nil;
  ASN1_STRING_new := nil;
  ASN1_STRING_free := nil;
  ASN1_STRING_clear_free := nil;
  ASN1_STRING_copy := nil;
  ASN1_STRING_dup := nil;
  ASN1_STRING_type_new := nil;
  ASN1_STRING_cmp := nil;
  ASN1_STRING_set := nil;
  ASN1_STRING_set0 := nil;
  ASN1_STRING_length := nil;
  ASN1_STRING_length_set := nil;
  ASN1_STRING_type := nil;
  ASN1_STRING_get0_data := nil;
  ASN1_BIT_STRING_set := nil;
  ASN1_BIT_STRING_set_bit := nil;
  ASN1_BIT_STRING_get_bit := nil;
  ASN1_BIT_STRING_check := nil;
  ASN1_BIT_STRING_name_print := nil;
  ASN1_BIT_STRING_num_asc := nil;
  ASN1_BIT_STRING_set_asc := nil;
  ASN1_INTEGER_new := nil;
  ASN1_INTEGER_free := nil;
  d2i_ASN1_INTEGER := nil;
  i2d_ASN1_INTEGER := nil;
  d2i_ASN1_UINTEGER := nil;
  ASN1_INTEGER_dup := nil;
  ASN1_INTEGER_cmp := nil;
  ASN1_UTCTIME_check := nil;
  ASN1_UTCTIME_set := nil;
  ASN1_UTCTIME_adj := nil;
  ASN1_UTCTIME_set_string := nil;
  ASN1_UTCTIME_cmp_time_t := nil;
  ASN1_GENERALIZEDTIME_check := nil;
  ASN1_GENERALIZEDTIME_set := nil;
  ASN1_GENERALIZEDTIME_adj := nil;
  ASN1_GENERALIZEDTIME_set_string := nil;
  ASN1_TIME_diff := nil;
  ASN1_OCTET_STRING_dup := nil;
  ASN1_OCTET_STRING_cmp := nil;
  ASN1_OCTET_STRING_set := nil;
  ASN1_OCTET_STRING_new := nil;
  ASN1_OCTET_STRING_free := nil;
  d2i_ASN1_OCTET_STRING := nil;
  i2d_ASN1_OCTET_STRING := nil;
  UTF8_getc := nil;
  UTF8_putc := nil;
  ASN1_UTCTIME_new := nil;
  ASN1_UTCTIME_free := nil;
  d2i_ASN1_UTCTIME := nil;
  i2d_ASN1_UTCTIME := nil;
  ASN1_GENERALIZEDTIME_new := nil;
  ASN1_GENERALIZEDTIME_free := nil;
  d2i_ASN1_GENERALIZEDTIME := nil;
  i2d_ASN1_GENERALIZEDTIME := nil;
  ASN1_TIME_new := nil;
  ASN1_TIME_free := nil;
  d2i_ASN1_TIME := nil;
  i2d_ASN1_TIME := nil;
  ASN1_TIME_set := nil;
  ASN1_TIME_adj := nil;
  ASN1_TIME_check := nil;
  ASN1_TIME_to_generalizedtime := nil;
  ASN1_TIME_set_string := nil;
  ASN1_TIME_set_string_X509 := nil;
  ASN1_TIME_to_tm := nil;
  ASN1_TIME_normalize := nil;
  ASN1_TIME_cmp_time_t := nil;
  ASN1_TIME_compare := nil;
  i2a_ASN1_INTEGER := nil;
  a2i_ASN1_INTEGER := nil;
  i2a_ASN1_ENUMERATED := nil;
  a2i_ASN1_ENUMERATED := nil;
  i2a_ASN1_OBJECT := nil;
  a2i_ASN1_STRING := nil;
  i2a_ASN1_STRING := nil;
  i2t_ASN1_OBJECT := nil;
  a2d_ASN1_OBJECT := nil;
  ASN1_OBJECT_create := nil;
  ASN1_INTEGER_get_int64 := nil;
  ASN1_INTEGER_set_int64 := nil;
  ASN1_INTEGER_get_uint64 := nil;
  ASN1_INTEGER_set_uint64 := nil;
  ASN1_INTEGER_set := nil;
  ASN1_INTEGER_get := nil;
  BN_to_ASN1_INTEGER := nil;
  ASN1_INTEGER_to_BN := nil;
  ASN1_ENUMERATED_get_int64 := nil;
  ASN1_ENUMERATED_set_int64 := nil;
  ASN1_ENUMERATED_set := nil;
  ASN1_ENUMERATED_get := nil;
  BN_to_ASN1_ENUMERATED := nil;
  ASN1_ENUMERATED_to_BN := nil;
  ASN1_PRINTABLE_type := nil;
  ASN1_tag2bit := nil;
  ASN1_get_object := nil;
  ASN1_check_infinite_end := nil;
  ASN1_const_check_infinite_end := nil;
  ASN1_put_object := nil;
  ASN1_put_eoc := nil;
  ASN1_object_size := nil;
  ASN1_item_dup := nil;
  ASN1_STRING_to_UTF8 := nil;
  ASN1_d2i_bio := nil;
  ASN1_item_d2i_bio := nil;
  ASN1_i2d_bio := nil;
  ASN1_item_i2d_bio := nil;
  ASN1_UTCTIME_print := nil;
  ASN1_GENERALIZEDTIME_print := nil;
  ASN1_TIME_print := nil;
  ASN1_STRING_print := nil;
  ASN1_STRING_print_ex := nil;
  ASN1_buf_print := nil;
  ASN1_bn_print := nil;
  ASN1_parse := nil;
  ASN1_parse_dump := nil;
  ASN1_tag2str := nil;
  ASN1_UNIVERSALSTRING_to_string := nil;
  ASN1_TYPE_set_octetstring := nil;
  ASN1_TYPE_get_octetstring := nil;
  ASN1_TYPE_set_int_octetstring := nil;
  ASN1_TYPE_get_int_octetstring := nil;
  ASN1_item_unpack := nil;
  ASN1_item_pack := nil;
  ASN1_STRING_set_default_mask := nil;
  ASN1_STRING_set_default_mask_asc := nil;
  ASN1_STRING_get_default_mask := nil;
  ASN1_mbstring_copy := nil;
  ASN1_mbstring_ncopy := nil;
  ASN1_STRING_set_by_NID := nil;
  ASN1_STRING_TABLE_get := nil;
  ASN1_STRING_TABLE_add := nil;
  ASN1_STRING_TABLE_cleanup := nil;
  ASN1_item_new := nil;
  ASN1_item_free := nil;
  ASN1_item_d2i := nil;
  ASN1_item_i2d := nil;
  ASN1_item_ndef_i2d := nil;
  ASN1_add_oid_module := nil;
  ASN1_add_stable_module := nil;
  ASN1_generate_nconf := nil;
  ASN1_generate_v3 := nil;
  ASN1_str2mask := nil;
  ASN1_item_print := nil;
  ASN1_PCTX_new := nil;
  ASN1_PCTX_free := nil;
  ASN1_PCTX_get_flags := nil;
  ASN1_PCTX_set_flags := nil;
  ASN1_PCTX_get_nm_flags := nil;
  ASN1_PCTX_set_nm_flags := nil;
  ASN1_PCTX_get_cert_flags := nil;
  ASN1_PCTX_set_cert_flags := nil;
  ASN1_PCTX_get_oid_flags := nil;
  ASN1_PCTX_set_oid_flags := nil;
  ASN1_PCTX_get_str_flags := nil;
  ASN1_PCTX_set_str_flags := nil;
  ASN1_SCTX_free := nil;
  ASN1_SCTX_get_item := nil;
  ASN1_SCTX_get_template := nil;
  ASN1_SCTX_get_flags := nil;
  ASN1_SCTX_set_app_data := nil;
  ASN1_SCTX_get_app_data := nil;
  BIO_f_asn1 := nil;
  BIO_new_NDEF := nil;
  i2d_ASN1_bio_stream := nil;
  PEM_write_bio_ASN1_stream := nil;
  SMIME_read_ASN1 := nil;
  SMIME_crlf_copy := nil;
  SMIME_text := nil;
  ASN1_ITEM_lookup := nil;
  ASN1_ITEM_get := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
