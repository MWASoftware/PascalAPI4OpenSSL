--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/e_os2.h	2026-04-14 13:04:16.000000000 +0100
+++ e_os2.tmp	2026-05-19 11:14:11.122173040 +0100
@@ -207,10 +207,11 @@
 typedef INTN ossl_ssize_t;
 #define OSSL_SSIZE_MAX MAX_INTN
 #endif
+/*
 #elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || defined(__osf__) || defined(__sgi) || defined(__hpux) || defined(OPENSSL_SYS_VMS) || defined(__OpenBSD__)
 #include <inttypes.h>
 #undef OPENSSL_NO_INTTYPES_H
-/* Because the specs say that inttypes.h includes stdint.h if present */
+/ * Because the specs say that inttypes.h includes stdint.h if present * /
 #undef OPENSSL_NO_STDINT_H
 #elif defined(OPENSSL_SYS_TANDEM)
 #include <stdint.h>
@@ -218,6 +219,7 @@
 #else
 #include <stdint.h>
 #undef OPENSSL_NO_STDINT_H
+*/
 #endif
 
 #ifdef _WIN32
@@ -238,54 +240,66 @@
 #elif defined(_POSIX_SSIZE_MAX)
 #define OSSL_SSIZE_MAX _POSIX_SSIZE_MAX
 #else
-#define OSSL_SSIZE_MAX ((ssize_t)(SIZE_MAX >> 1))
+#define OSSL_SSIZE_MAX SIZE_MAX>>1)
 #endif
 #endif
 
+/*
 #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && defined(INTMAX_MAX) && defined(UINTMAX_MAX)
 typedef intmax_t ossl_intmax_t;
 typedef uintmax_t ossl_uintmax_t;
 #else
+*/
 /* Fall back to the largest we know we require and can handle */
 typedef int64_t ossl_intmax_t;
 typedef uint64_t ossl_uintmax_t;
-#endif
+// #endif
 
 /* ossl_inline: portable inline definition usable in public headers */
+/*
 #if !defined(inline) && !defined(__cplusplus)
 #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
-/* just use inline */
+/ * just use inline * /
 #define ossl_inline inline
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
+*/
 #define ossl_inline
+/*
 #endif
 #else
 #define ossl_inline inline
 #endif
+*/
 
+/*
 #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
 #define ossl_noreturn _Noreturn
 #elif defined(__GNUC__) && __GNUC__ >= 2
+*/
 #define ossl_noreturn __attribute__((noreturn))
+/*
 #else
 #define ossl_noreturn
 #endif
+*/
 
 /* ossl_unused: portable unused attribute for use in public headers */
-#if defined(__GNUC__)
+//#if defined(__GNUC__)
 #define ossl_unused __attribute__((unused))
+/*
 #else
 #define ossl_unused
 #endif
+*/
 
 #ifdef __cplusplus
 }
