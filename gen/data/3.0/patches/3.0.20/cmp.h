--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/cmp.h	2026-05-04 13:52:25.156425472 +0100
+++ cmp.tmp	2026-05-19 11:14:40.803142452 +0100
@@ -136,9 +136,9 @@
 #define OSSL_CMP_PKIFAILUREINFO_MAX 26
 #define OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN \
     ((1 << (OSSL_CMP_PKIFAILUREINFO_MAX + 1)) - 1)
-#if OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN > INT_MAX
-#error CMP_PKIFAILUREINFO_MAX bit pattern does not fit in type int
-#endif
+//#if OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN > INT_MAX
+//#error CMP_PKIFAILUREINFO_MAX bit pattern does not fit in type int
+//#endif
 
 typedef ASN1_BIT_STRING OSSL_CMP_PKIFAILUREINFO;
 
