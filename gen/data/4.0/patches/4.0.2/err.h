--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.2/include/openssl/err.h	2026-09-16 14:39:15.381411271 +0100
+++ err.tmp	2026-09-16 14:55:48.111326688 +0100
@@ -242,12 +242,12 @@
     return errcode & ERR_REASON_MASK;
 }
 
-static ossl_unused ossl_inline int ERR_FATAL_ERROR(unsigned long errcode)
+static ossl_unused ossl_inline bool ERR_FATAL_ERROR(unsigned long errcode)
 {
     return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_FATAL) != 0;
 }
 
-static ossl_unused ossl_inline int ERR_COMMON_ERROR(unsigned long errcode)
+static ossl_unused ossl_inline bool ERR_COMMON_ERROR(unsigned long errcode)
 {
     return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_COMMON) != 0;
 }
