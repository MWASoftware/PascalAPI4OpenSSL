--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/asn1.h	2026-05-09 15:58:59.234656983 +0100
+++ asn1.tmp	2026-05-19 11:14:11.073173091 +0100
@@ -162,7 +162,7 @@
 /* clang-format on */
 
 /* This is the base type that holds just about everything :-) */
-struct asn1_string_st;
+// struct asn1_string_st; Moved to types
 
 /*
  * ASN1_ENCODING structure: this is used to save the received encoding of an
@@ -183,6 +183,7 @@
 /*
  * A zero passed to ASN1_STRING_TABLE_new_add for the flags is interpreted
  * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
+/* Moved to types.h
  * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
  * STABLE_FLAGS_CLEAR to reflect this.
  */
@@ -198,7 +199,7 @@
     long maxsize;
     unsigned long mask;
     unsigned long flags;
-};
+};*/
 
 /* clang-format off */
 SKM_DEFINE_STACK_OF_INTERNAL(ASN1_STRING_TABLE, ASN1_STRING_TABLE, ASN1_STRING_TABLE)
