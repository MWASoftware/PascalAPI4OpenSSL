--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/types.h	2026-04-07 13:46:26.000000000 +0100
+++ types.tmp	2026-05-19 11:14:40.885142367 +0100
@@ -21,28 +21,24 @@
 #include <openssl/safestack.h>
 #include <openssl/macros.h>
 
-typedef struct ossl_provider_st OSSL_PROVIDER; /* Provider Object */
+/* This is the base type that holds just about everything :-) */
+/* moved from asn1.h */
+struct asn1_string_st {
+    int length;
+    int type;
+    unsigned char *data;
+    /*
+     * The value of the following field depends on the type being held.  It
+     * is mostly being used for BIT_STRING so if the input data has a
+     * non-zero 'unused bits' value, it will be handled correctly
+     */
+    long flags;
+};
 
-#ifdef NO_ASN1_TYPEDEFS
-#define ASN1_INTEGER ASN1_STRING
-#define ASN1_ENUMERATED ASN1_STRING
-#define ASN1_BIT_STRING ASN1_STRING
-#define ASN1_OCTET_STRING ASN1_STRING
-#define ASN1_PRINTABLESTRING ASN1_STRING
-#define ASN1_T61STRING ASN1_STRING
-#define ASN1_IA5STRING ASN1_STRING
-#define ASN1_UTCTIME ASN1_STRING
-#define ASN1_GENERALIZEDTIME ASN1_STRING
-#define ASN1_TIME ASN1_STRING
-#define ASN1_GENERALSTRING ASN1_STRING
-#define ASN1_UNIVERSALSTRING ASN1_STRING
-#define ASN1_BMPSTRING ASN1_STRING
-#define ASN1_VISIBLESTRING ASN1_STRING
-#define ASN1_UTF8STRING ASN1_STRING
-#define ASN1_BOOLEAN int
-#define ASN1_NULL int
-#else
+typedef struct ossl_provider_st OSSL_PROVIDER; /* Provider Object */
 typedef struct asn1_string_st ASN1_INTEGER;
+
+#ifndef NO_ASN1_TYPEDEFS
 typedef struct asn1_string_st ASN1_ENUMERATED;
 typedef struct asn1_string_st ASN1_BIT_STRING;
 typedef struct asn1_string_st ASN1_OCTET_STRING;
@@ -60,6 +56,24 @@
 typedef struct asn1_string_st ASN1_STRING;
 typedef int ASN1_BOOLEAN;
 typedef int ASN1_NULL;
+#else
+#define ASN1_INTEGER ASN1_STRING
+#define ASN1_ENUMERATED ASN1_STRING
+#define ASN1_BIT_STRING ASN1_STRING
+#define ASN1_OCTET_STRING ASN1_STRING
+#define ASN1_PRINTABLESTRING ASN1_STRING
+#define ASN1_T61STRING ASN1_STRING
+#define ASN1_IA5STRING ASN1_STRING
+#define ASN1_UTCTIME ASN1_STRING
+#define ASN1_GENERALIZEDTIME ASN1_STRING
+#define ASN1_TIME ASN1_STRING
+#define ASN1_GENERALSTRING ASN1_STRING
+#define ASN1_UNIVERSALSTRING ASN1_STRING
+#define ASN1_BMPSTRING ASN1_STRING
+#define ASN1_VISIBLESTRING ASN1_STRING
+#define ASN1_UTF8STRING ASN1_STRING
+#define ASN1_BOOLEAN int
+#define ASN1_NULL int
 #endif
 
 typedef struct asn1_type_st ASN1_TYPE;
