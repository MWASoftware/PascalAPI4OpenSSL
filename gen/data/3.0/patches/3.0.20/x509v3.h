--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/x509v3.h	2026-05-04 13:52:26.477428723 +0100
+++ x509v3.tmp	2026-05-19 11:14:40.891142361 +0100
@@ -88,12 +88,12 @@
 } X509V3_CONF_METHOD;
 
 /* Context specific info for producing X509 v3 extensions*/
-struct v3_ext_ctx {
 #define X509V3_CTX_TEST 0x1
 #ifndef OPENSSL_NO_DEPRECATED_3_0
 #define CTX_TEST X509V3_CTX_TEST
 #endif
 #define X509V3_CTX_REPLACE 0x2
+struct v3_ext_ctx {
     int flags;
     X509 *issuer_cert;
     X509 *subject_cert;
