--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.4/include/openssl/err.h	2026-09-16 14:58:06.658314885 +0100
+++ err.tmp	2026-09-16 15:16:05.792222895 +0100
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
