--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.2/include/openssl/rand.h	2026-08-25 12:38:35.000000000 +0100
+++ rand.tmp	2026-09-16 14:55:48.135326686 +0100
@@ -93,7 +93,7 @@
 void RAND_keep_random_devices_open(int keep);
 
 #if defined(__ANDROID__) && defined(__NDK_FPABI__)
-__NDK_FPABI__ /* __attribute__((pcs("aapcs"))) on ARM */
+//__NDK_FPABI__ /* __attribute__((pcs("aapcs"))) on ARM */
 #endif
     void RAND_add(const void *buf, int num, double randomness);
 int RAND_load_file(const char *file, long max_bytes);
