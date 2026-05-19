--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/err.h	2026-05-04 13:52:25.551426444 +0100
+++ err.tmp	2026-05-19 11:14:40.825142429 +0100
@@ -261,12 +261,12 @@
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
