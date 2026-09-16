--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.2/include/openssl/safestack.h	2026-09-16 14:39:15.974411220 +0100
+++ safestack.tmp	2026-09-16 14:55:48.140326686 +0100
@@ -30,7 +30,10 @@
 extern "C" {
 #endif
 
+
 #define STACK_OF(type) struct stack_st_##type
+STACK_OF(char);
+STACK_OF(void);
 
 /* Helper macro for internal use */
 #define SKM_DEFINE_STACK_OF_INTERNAL(t1, t2, t3)                                                                         \
