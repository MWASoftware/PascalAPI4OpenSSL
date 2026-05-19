--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/macros.h	2026-04-14 13:04:16.000000000 +0100
+++ macros.tmp	2026-05-19 11:14:11.132173030 +0100
@@ -11,7 +11,7 @@
 #define OPENSSL_MACROS_H
 #pragma once
 
-#include <openssl/opensslconf.h>
+#include <openssl/configuration.h>
 #include <openssl/opensslv.h>
 
 /* Helper macros for CPP string composition */
@@ -33,11 +33,12 @@
 #ifndef OSSL_DEPRECATED
 #undef OSSL_DEPRECATED_FOR
 #ifndef OPENSSL_SUPPRESS_DEPRECATED
-#if defined(_MSC_VER)
+//#if defined(_MSC_VER)
 /*
  * MSVC supports __declspec(deprecated) since MSVC 2003 (13.10),
  * and __declspec(deprecated(message)) since MSVC 2005 (14.00)
  */
+ /* Commented out to avoid Delphi errors
 #if _MSC_VER >= 1400
 #define OSSL_DEPRECATED(since) \
     __declspec(deprecated("Since OpenSSL " #since))
@@ -53,10 +54,10 @@
     __pragma(warning(push)) __pragma(warning(disable : 4996))
 #define OSSL_END_ALLOW_DEPRECATED __pragma(warning(pop))
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
@@ -71,7 +72,9 @@
 #define OSSL_BEGIN_ALLOW_DEPRECATED \
     _Pragma("GCC diagnostic push")  \
         _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
+*/
 #define OSSL_END_ALLOW_DEPRECATED _Pragma("GCC diagnostic pop")
+/*
 #elif defined(__SUNPRO_C)
 #if (__SUNPRO_C >= 0x5130)
 #define OSSL_DEPRECATED(since) __attribute__((deprecated))
@@ -83,6 +86,7 @@
 #define OSSL_END_ALLOW_DEPRECATED \
     #pragma error_messages(on, E_DEPRECATED_ATT, E_DEPRECATED_ATT_MESS)
 #endif
+*/
 #endif
 #endif
 
@@ -164,14 +168,16 @@
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
@@ -332,11 +338,10 @@
 #define OSSL_DEPRECATEDIN_0_9_8
 #define OSSL_DEPRECATEDIN_0_9_8_FOR(msg)
 #endif
-
 /*
  * Make our own variants of __FILE__ and __LINE__, depending on configuration
  */
-
+/*
 #ifndef OPENSSL_FILE
 #ifdef OPENSSL_NO_FILENAMES
 #define OPENSSL_FILE ""
@@ -346,7 +351,7 @@
 #define OPENSSL_LINE __LINE__
 #endif
 #endif
-
+*/
 /*
  * __func__ was standardized in C99, so for any compiler that claims
  * to implement that language level or newer, we assume we can safely
@@ -360,6 +365,7 @@
  * If none of the above applies, we check if the compiler is MSVC,
  * and use __FUNCTION__ if that's the case.
  */
+/* Commented out to avoid Delphi errors
 #ifndef OPENSSL_FUNC
 #if defined(__STDC_VERSION__)
 #if __STDC_VERSION__ >= 199901L
@@ -370,6 +376,7 @@
 #elif defined(_MSC_VER)
 #define OPENSSL_FUNC __FUNCTION__
 #endif
+*/
 /*
  * If all these possibilities are exhausted, we give up and use a
  * static string.
@@ -377,7 +384,7 @@
 #ifndef OPENSSL_FUNC
 #define OPENSSL_FUNC "(unknown function)"
 #endif
-#endif
+//#endif
 
 #ifndef OSSL_CRYPTO_ALLOC
 #if defined(__GNUC__)
