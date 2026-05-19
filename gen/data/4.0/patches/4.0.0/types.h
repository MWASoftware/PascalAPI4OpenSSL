--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/types.h	2026-04-14 13:04:16.000000000 +0100
+++ types.tmp	2026-05-19 11:14:11.186172974 +0100
@@ -33,8 +33,24 @@
 #include <openssl/safestack.h>
 #include <openssl/macros.h>
 
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
+
+
 typedef struct ossl_provider_st OSSL_PROVIDER; /* Provider Object */
 
+/*
 #ifdef NO_ASN1_TYPEDEFS
 typedef ASN1_STRING ASN1_INTEGER;
 typedef ASN1_STRING ASN1_ENUMERATED;
@@ -54,6 +70,7 @@
 typedef int ASN1_BOOLEAN;
 typedef int ASN1_NULL;
 #else
+*/
 typedef struct asn1_string_st ASN1_INTEGER;
 typedef struct asn1_string_st ASN1_ENUMERATED;
 typedef struct asn1_string_st ASN1_BIT_STRING;
@@ -72,7 +89,7 @@
 typedef struct asn1_string_st ASN1_STRING;
 typedef int ASN1_BOOLEAN;
 typedef int ASN1_NULL;
-#endif
+//#endif
 
 typedef struct asn1_type_st ASN1_TYPE;
 typedef struct asn1_object_st ASN1_OBJECT;
