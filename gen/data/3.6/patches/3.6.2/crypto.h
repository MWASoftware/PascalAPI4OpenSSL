--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/crypto.h	2026-05-16 11:56:03.481333768 +0100
+++ crypto.tmp	2026-05-19 11:12:35.697271378 +0100
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
 
@@ -589,6 +570,27 @@
 
 int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));
 
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
 int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *));
 void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key);
 int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
