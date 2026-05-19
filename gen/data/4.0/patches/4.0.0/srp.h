--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/srp.h	2026-05-09 15:59:00.694658379 +0100
+++ srp.tmp	2026-05-19 11:14:11.158173003 +0100
@@ -40,6 +40,9 @@
 extern "C" {
 #endif
 
+typedef stack_st_SRP SRP;
+SKM_DEFINE_STACK_OF_INTERNAL(SRP,SRP,SRP);
+
 #ifndef OPENSSL_NO_DEPRECATED_3_0
 
 typedef struct SRP_gN_cache_st {
