24a25
> typedef struct asn1_string_st ASN1_STRING;
26,44c27
< # ifdef NO_ASN1_TYPEDEFS
< #  define ASN1_INTEGER            ASN1_STRING
< #  define ASN1_ENUMERATED         ASN1_STRING
< #  define ASN1_BIT_STRING         ASN1_STRING
< #  define ASN1_OCTET_STRING       ASN1_STRING
< #  define ASN1_PRINTABLESTRING    ASN1_STRING
< #  define ASN1_T61STRING          ASN1_STRING
< #  define ASN1_IA5STRING          ASN1_STRING
< #  define ASN1_UTCTIME            ASN1_STRING
< #  define ASN1_GENERALIZEDTIME    ASN1_STRING
< #  define ASN1_TIME               ASN1_STRING
< #  define ASN1_GENERALSTRING      ASN1_STRING
< #  define ASN1_UNIVERSALSTRING    ASN1_STRING
< #  define ASN1_BMPSTRING          ASN1_STRING
< #  define ASN1_VISIBLESTRING      ASN1_STRING
< #  define ASN1_UTF8STRING         ASN1_STRING
< #  define ASN1_BOOLEAN            int
< #  define ASN1_NULL               int
< # else
---
> # ifndef NO_ASN1_TYPEDEFS
60d42
< typedef struct asn1_string_st ASN1_STRING;
62a45,62
> # else
> #  define ASN1_INTEGER            ASN1_STRING
> #  define ASN1_ENUMERATED         ASN1_STRING
> #  define ASN1_BIT_STRING         ASN1_STRING
> #  define ASN1_OCTET_STRING       ASN1_STRING
> #  define ASN1_PRINTABLESTRING    ASN1_STRING
> #  define ASN1_T61STRING          ASN1_STRING
> #  define ASN1_IA5STRING          ASN1_STRING
> #  define ASN1_UTCTIME            ASN1_STRING
> #  define ASN1_GENERALIZEDTIME    ASN1_STRING
> #  define ASN1_TIME               ASN1_STRING
> #  define ASN1_GENERALSTRING      ASN1_STRING
> #  define ASN1_UNIVERSALSTRING    ASN1_STRING
> #  define ASN1_BMPSTRING          ASN1_STRING
> #  define ASN1_VISIBLESTRING      ASN1_STRING
> #  define ASN1_UTF8STRING         ASN1_STRING
> #  define ASN1_BOOLEAN            int
> #  define ASN1_NULL               int
