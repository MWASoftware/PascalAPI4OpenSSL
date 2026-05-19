--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/asn1t.h	2026-05-16 11:56:02.922333293 +0100
+++ asn1t.tmp	2026-05-19 11:12:35.665271410 +0100
@@ -485,8 +485,8 @@
 
 /* Macro to extract ASN1_ITEM and ASN1_ADB pointer from ASN1_TEMPLATE */
 
-#define ASN1_TEMPLATE_item(t) (t->item_ptr)
-#define ASN1_TEMPLATE_adb(t) (t->item_ptr)
+#define ASN1_TEMPLATE_item(t) (t->item)
+#define ASN1_TEMPLATE_adb(t) (t->item)
 
 typedef struct ASN1_ADB_TABLE_st ASN1_ADB_TABLE;
 typedef struct ASN1_ADB_st ASN1_ADB;
@@ -540,11 +540,7 @@
 
 #define ASN1_TFLG_TAG_MASK (0x3 << 3)
 
-/* context specific IMPLICIT */
-#define ASN1_TFLG_IMPLICIT (ASN1_TFLG_IMPTAG | ASN1_TFLG_CONTEXT)
 
-/* context specific EXPLICIT */
-#define ASN1_TFLG_EXPLICIT (ASN1_TFLG_EXPTAG | ASN1_TFLG_CONTEXT)
 
 /*
  * If tagging is in force these determine the type of tag to use. Otherwise
@@ -563,6 +559,14 @@
 
 #define ASN1_TFLG_TAG_CLASS (0x3 << 6)
 
+/* context specific IMPLICIT */
+#define ASN1_TFLG_IMPLICIT (ASN1_TFLG_IMPTAG | ASN1_TFLG_CONTEXT)
+
+/* context specific EXPLICIT */
+#define ASN1_TFLG_EXPLICIT (ASN1_TFLG_EXPTAG | ASN1_TFLG_CONTEXT)
+
+
+
 /*
  * These are for ANY DEFINED BY type. In this case the 'item' field points to
  * an ASN1_ADB structure which contains a table of values to decode the
