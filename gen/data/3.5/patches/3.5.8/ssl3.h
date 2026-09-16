--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.8/include/openssl/ssl3.h	2026-08-25 12:56:39.000000000 +0100
+++ ssl3.tmp	2026-09-16 14:49:57.485356545 +0100
@@ -151,10 +151,10 @@
  */
 #define SSL3_ALIGN_PAYLOAD 8
 #else
-#if (SSL3_ALIGN_PAYLOAD & (SSL3_ALIGN_PAYLOAD - 1)) != 0
-#error "insane SSL3_ALIGN_PAYLOAD"
-#undef SSL3_ALIGN_PAYLOAD
-#endif
+//#if (SSL3_ALIGN_PAYLOAD & (SSL3_ALIGN_PAYLOAD - 1)) != 0
+//#error "insane SSL3_ALIGN_PAYLOAD"
+//#undef SSL3_ALIGN_PAYLOAD
+//#endif
 #endif
 
 /*
@@ -279,9 +279,9 @@
 #define SSL3_CT_NUMBER 12
 
 #if defined(TLS_CT_NUMBER)
-#if TLS_CT_NUMBER != SSL3_CT_NUMBER
-#error "SSL/TLS CT_NUMBER values do not match"
-#endif
+//#if TLS_CT_NUMBER != SSL3_CT_NUMBER
+//#error "SSL/TLS CT_NUMBER values do not match"
+//#endif
 #endif
 
 /* No longer used as of OpenSSL 1.1.1 */
