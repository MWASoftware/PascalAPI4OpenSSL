--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/crypto.h	2026-05-09 15:58:59.897657617 +0100
+++ crypto.tmp	2026-05-19 11:14:11.111173051 +0100
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
 
@@ -557,6 +538,27 @@
 
 #if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
 #if defined(_WIN32)
+
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
 #if defined(BASETYPES) || defined(_WINDEF_H)
 /* application has to include <windows.h> in order to use this */
 typedef DWORD CRYPTO_THREAD_LOCAL;
