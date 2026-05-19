--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/srp.h	2026-05-16 11:56:04.247334419 +0100
+++ srp.tmp	2026-05-19 11:12:35.744271330 +0100
@@ -40,6 +40,9 @@
 extern "C" {
 #endif
 
+typedef stack_st_SRP SRP;
+SKM_DEFINE_STACK_OF_INTERNAL(SRP,SRP,SRP);
+
 #ifndef OPENSSL_NO_DEPRECATED_3_0
 
 typedef struct SRP_gN_cache_st {
