--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.8/include/openssl/srp.h	2026-09-16 14:28:03.600468535 +0100
+++ srp.tmp	2026-09-16 14:49:57.474356546 +0100
@@ -40,6 +40,9 @@
 extern "C" {
 #endif
 
+typedef stack_st_SRP SRP;
+SKM_DEFINE_STACK_OF_INTERNAL(SRP,SRP,SRP);
+
 #ifndef OPENSSL_NO_DEPRECATED_3_0
 
 typedef struct SRP_gN_cache_st {
