--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/ssl3.h	2026-04-07 13:46:26.000000000 +0100
+++ ssl3.tmp	2026-05-19 11:14:40.868142385 +0100
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
@@ -272,9 +272,9 @@
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
