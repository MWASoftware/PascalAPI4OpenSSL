--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/macros.h	2026-04-07 13:17:57.000000000 +0100
+++ macros.tmp	2026-05-19 11:12:35.717271358 +0100
@@ -11,7 +11,7 @@
 #define OPENSSL_MACROS_H
 #pragma once
 
-#include <openssl/opensslconf.h>
+#include <openssl/configuration.h>
 #include <openssl/opensslv.h>
 
 /* Helper macros for CPP string composition */
@@ -47,11 +47,12 @@
 #define OSSL_DEPRECATED(since) __declspec(deprecated)
 #define OSSL_DEPRECATED_FOR(since, message) __declspec(deprecated)
 #endif
+/* Commented out to avoid Delphi errors
 #elif defined(__GNUC__)
-/*
+/ *
  * According to GCC documentation, deprecations with message appeared in
  * GCC 4.5.0
- */
+ * /
 #if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
 #define OSSL_DEPRECATED(since) \
     __attribute__((deprecated("Since OpenSSL " #since)))
@@ -66,6 +67,7 @@
 #define OSSL_DEPRECATED(since) __attribute__((deprecated))
 #define OSSL_DEPRECATED_FOR(since, message) __attribute__((deprecated))
 #endif
+*/
 #endif
 #endif
 #endif
@@ -145,14 +147,16 @@
 #if OPENSSL_API_LEVEL > (OPENSSL_VERSION_MAJOR * 10000 + OPENSSL_VERSION_MINOR * 100)
 #error "OPENSSL_API_COMPAT expresses an impossible API compatibility level"
 #endif
-/* OpenSSL will have no version 2.y.z */
+/*Commented out to avoid Delphi errors
+/ * OpenSSL will have no version 2.y.z * /
 #if OPENSSL_API_LEVEL < 30000 && OPENSSL_API_LEVEL >= 20000
 #error "OPENSSL_API_COMPAT expresses an impossible API compatibility level"
 #endif
-/* Below 0.9.8 is unacceptably low */
+/ * Below 0.9.8 is unacceptably low * /
 #if OPENSSL_API_LEVEL < 908
 #error "OPENSSL_API_COMPAT expresses an impossible API compatibility level"
 #endif
+*/
 
 /*
  * Define macros for deprecation and simulated removal purposes.
@@ -301,7 +305,7 @@
 #define OSSL_DEPRECATEDIN_0_9_8
 #define OSSL_DEPRECATEDIN_0_9_8_FOR(msg)
 #endif
-
+/*
 /*
  * Make our own variants of __FILE__ and __LINE__, depending on configuration
  */
@@ -315,7 +319,7 @@
 #define OPENSSL_LINE __LINE__
 #endif
 #endif
-
+*/
 /*
  * __func__ was standardized in C99, so for any compiler that claims
  * to implement that language level or newer, we assume we can safely
@@ -330,6 +334,7 @@
  * and use __FUNCTION__ if that's the case.
  */
 #ifndef OPENSSL_FUNC
+/* Commented out to avoid Delphi errors
 #if defined(__STDC_VERSION__)
 #if __STDC_VERSION__ >= 199901L
 #define OPENSSL_FUNC __func__
@@ -339,6 +344,7 @@
 #elif defined(_MSC_VER)
 #define OPENSSL_FUNC __FUNCTION__
 #endif
+*/
 /*
  * If all these possibilities are exhausted, we give up and use a
  * static string.
