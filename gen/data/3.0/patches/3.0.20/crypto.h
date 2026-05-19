--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/crypto.h	2026-05-04 13:52:25.417426114 +0100
+++ crypto.tmp	2026-05-19 11:14:40.809142446 +0100
@@ -36,7 +36,7 @@
 #include <openssl/safestack.h>
 #include <openssl/opensslv.h>
 #include <openssl/types.h>
-#include <openssl/opensslconf.h>
+#include <openssl/configuration.h>
 #include <openssl/cryptoerr.h>
 #include <openssl/core.h>
 
@@ -58,25 +58,6 @@
 extern "C" {
 #endif
 
-#ifndef OPENSSL_NO_DEPRECATED_1_1_0
-#define SSLeay OpenSSL_version_num
-#define SSLeay_version OpenSSL_version
-#define SSLEAY_VERSION_NUMBER OPENSSL_VERSION_NUMBER
-#define SSLEAY_VERSION OPENSSL_VERSION
-#define SSLEAY_CFLAGS OPENSSL_CFLAGS
-#define SSLEAY_BUILT_ON OPENSSL_BUILT_ON
-#define SSLEAY_PLATFORM OPENSSL_PLATFORM
-#define SSLEAY_DIR OPENSSL_DIR
-
-/*
- * Old type for allocating dynamic locks. No longer used. Use the new thread
- * API instead.
- */
-typedef struct {
-    int dummy;
-} CRYPTO_dynlock;
-
-#endif /* OPENSSL_NO_DEPRECATED_1_1_0 */
 
 typedef void CRYPTO_RWLOCK;
 
@@ -558,6 +539,27 @@
 OSSL_LIB_CTX *OSSL_LIB_CTX_get0_global_default(void);
 OSSL_LIB_CTX *OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX *libctx);
 
+#ifndef OPENSSL_NO_DEPRECATED_1_1_0
+#define SSLeay OpenSSL_version_num
+#define SSLeay_version OpenSSL_version
+#define SSLEAY_VERSION_NUMBER OPENSSL_VERSION_NUMBER
+#define SSLEAY_VERSION OPENSSL_VERSION
+#define SSLEAY_CFLAGS OPENSSL_CFLAGS
+#define SSLEAY_BUILT_ON OPENSSL_BUILT_ON
+#define SSLEAY_PLATFORM OPENSSL_PLATFORM
+#define SSLEAY_DIR OPENSSL_DIR
+
+/*
+ * Old type for allocating dynamic locks. No longer used. Use the new thread
+ * API instead.
+ */
+typedef struct {
+    int dummy;
+} CRYPTO_dynlock;
+
+#endif /* OPENSSL_NO_DEPRECATED_1_1_0 */
+
+
 #ifdef __cplusplus
 }
 #endif
