--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.6/include/openssl/srp.h	2026-05-08 16:06:48.342981362 +0100
+++ srp.tmp	2026-05-19 11:11:57.535310705 +0100
@@ -40,6 +40,9 @@
 extern "C" {
 #endif
 
+typedef stack_st_SRP SRP;
+SKM_DEFINE_STACK_OF_INTERNAL(SRP,SRP,SRP);
+
 #ifndef OPENSSL_NO_DEPRECATED_3_0
 
 typedef struct SRP_gN_cache_st {
