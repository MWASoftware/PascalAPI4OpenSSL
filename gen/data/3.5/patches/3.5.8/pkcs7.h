--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.8/include/openssl/pkcs7.h	2026-09-16 14:28:03.459468547 +0100
+++ pkcs7.tmp	2026-09-16 14:49:57.458356547 +0100
@@ -191,9 +191,6 @@
      */
     unsigned char *asn1;
     long length;
-#define PKCS7_S_HEADER 0
-#define PKCS7_S_BODY 1
-#define PKCS7_S_TAIL 2
     int state; /* used during processing */
     int detached;
     ASN1_OBJECT *type;
@@ -221,6 +218,9 @@
     } d;
     PKCS7_CTX ctx;
 } PKCS7;
+#define PKCS7_S_HEADER 0
+#define PKCS7_S_BODY 1
+#define PKCS7_S_TAIL 2
 /* clang-format off */
 SKM_DEFINE_STACK_OF_INTERNAL(PKCS7, PKCS7, PKCS7)
 #define sk_PKCS7_num(sk) OPENSSL_sk_num(ossl_check_const_PKCS7_sk_type(sk))
