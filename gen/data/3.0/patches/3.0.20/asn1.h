--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/asn1.h	2026-05-04 13:52:24.953424972 +0100
+++ asn1.tmp	2026-05-19 11:14:40.787142468 +0100
@@ -183,6 +183,7 @@
 /* String should be parsed in RFC 5280's time format */
 #define ASN1_STRING_FLAG_X509_TIME 0x100
 /* This is the base type that holds just about everything :-) */
+/* Moved to types.h
 struct asn1_string_st {
     int length;
     int type;
@@ -193,7 +194,7 @@
      * non-zero 'unused bits' value, it will be handled correctly
      */
     long flags;
-};
+};*/
 
 /*
  * ASN1_ENCODING structure: this is used to save the received encoding of an
