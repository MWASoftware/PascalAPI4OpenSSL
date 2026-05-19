--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/safestack.h	2026-05-09 15:59:00.622658310 +0100
+++ safestack.tmp	2026-05-19 11:14:11.153173008 +0100
@@ -30,7 +30,10 @@
 extern "C" {
 #endif
 
+
 #define STACK_OF(type) struct stack_st_##type
+STACK_OF(char);
+STACK_OF(void);
 
 /* Helper macro for internal use */
 #define SKM_DEFINE_STACK_OF_INTERNAL(t1, t2, t3)                                                                         \
