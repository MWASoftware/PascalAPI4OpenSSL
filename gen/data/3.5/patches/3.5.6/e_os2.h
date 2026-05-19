--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.6/include/openssl/e_os2.h	2026-04-07 13:26:30.000000000 +0100
+++ e_os2.tmp	2026-05-19 11:11:57.497310744 +0100
@@ -207,7 +207,7 @@
 #elif defined(_POSIX_SSIZE_MAX)
 #define OSSL_SSIZE_MAX _POSIX_SSIZE_MAX
 #else
-#define OSSL_SSIZE_MAX ((ssize_t)(SIZE_MAX >> 1))
+#define OSSL_SSIZE_MAX SIZE_MAX>>1)
 #endif
 #endif
 
@@ -230,11 +230,11 @@
 typedef INT64 int64_t;
 typedef UINT64 uint64_t;
 typedef UINTN uintptr_t;
-#elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || defined(__osf__) || defined(__sgi) || defined(__hpux) || defined(OPENSSL_SYS_VMS) || defined(__OpenBSD__)
+/* #elif  __STDC_VERSION__ >= 199901L || defined(__osf__) || defined(__sgi) || defined(__hpux) || defined(OPENSSL_SYS_VMS) || defined(__OpenBSD__)
 #include <inttypes.h>
 #undef OPENSSL_NO_INTTYPES_H
 /* Because the specs say that inttypes.h includes stdint.h if present */
-#undef OPENSSL_NO_STDINT_H
+#undef OPENSSL_NO_STDINT_H 
 #elif defined(_MSC_VER) && _MSC_VER < 1600
 /*
  * minimally required typdefs for systems not supporting inttypes.h or
@@ -248,6 +248,7 @@
 typedef unsigned int uint32_t;
 typedef __int64 int64_t;
 typedef unsigned __int64 uint64_t;
+*/
 #elif defined(OPENSSL_SYS_TANDEM)
 #include <stdint.h>
 #include <sys/types.h>
@@ -255,16 +256,18 @@
 #include <stdint.h>
 #undef OPENSSL_NO_STDINT_H
 #endif
+/* Commented out to avoid Delphi errors
 #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && defined(INTMAX_MAX) && defined(UINTMAX_MAX)
 typedef intmax_t ossl_intmax_t;
 typedef uintmax_t ossl_uintmax_t;
-#else
+#else */
 /* Fall back to the largest we know we require and can handle */
 typedef int64_t ossl_intmax_t;
 typedef uint64_t ossl_uintmax_t;
-#endif
+//#endif
 
 /* ossl_inline: portable inline definition usable in public headers */
+/* Causes runtime problems for Pascal - inline is reserved word
 #if !defined(inline) && !defined(__cplusplus)
 #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
 /* just use inline */
@@ -272,33 +275,38 @@
 #elif defined(__GNUC__) && __GNUC__ >= 2
 #define ossl_inline __inline__
 #elif defined(_MSC_VER)
-/*
+/ *
  * Visual Studio: inline is available in C++ only, however
  * __inline is available for C, see
  * http://msdn.microsoft.com/en-us/library/z8y1yy88.aspx
- */
+ * /
 #define ossl_inline __inline
 #else
 #define ossl_inline
 #endif
 #else
+*/
 #define ossl_inline inline
-#endif
+//#endif
 
-#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
-#define ossl_noreturn _Noreturn
+/* #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
+//#define ossl_noreturn _Noreturn
+#define ossl_noreturn
 #elif defined(__GNUC__) && __GNUC__ >= 2
+*/
 #define ossl_noreturn __attribute__((noreturn))
-#else
+/* #else
 #define ossl_noreturn
-#endif
+#endif 
+*/
 
 /* ossl_unused: portable unused attribute for use in public headers */
-#if defined(__GNUC__)
+// #if defined(__GNUC__)
 #define ossl_unused __attribute__((unused))
-#else
+/* #else
 #define ossl_unused
 #endif
+*/
 
 #ifdef __cplusplus
 }
