--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.6/include/openssl/asn1.h	2026-05-08 16:06:46.938980062 +0100
+++ asn1.tmp	2026-05-19 11:11:57.447310796 +0100
@@ -183,6 +183,7 @@
 #define ASN1_STRING_FLAG_MSTRING 0x040
 /* String is embedded and only content should be freed */
 #define ASN1_STRING_FLAG_EMBED 0x080
+/* Moved to types.h
 /* String should be parsed in RFC 5280's time format */
 #define ASN1_STRING_FLAG_X509_TIME 0x100
 /* This is the base type that holds just about everything :-) */
@@ -196,7 +197,7 @@
      * non-zero 'unused bits' value, it will be handled correctly
      */
     long flags;
-};
+};*/
 
 /*
  * ASN1_ENCODING structure: this is used to save the received encoding of an
