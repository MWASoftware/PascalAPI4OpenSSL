--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/rand.h	2026-04-07 13:46:26.000000000 +0100
+++ rand.tmp	2026-05-19 11:14:40.845142409 +0100
@@ -94,7 +94,7 @@
 void RAND_keep_random_devices_open(int keep);
 
 #if defined(__ANDROID__) && defined(__NDK_FPABI__)
-__NDK_FPABI__ /* __attribute__((pcs("aapcs"))) on ARM */
+//__NDK_FPABI__ /* __attribute__((pcs("aapcs"))) on ARM */
 #endif
     void RAND_add(const void *buf, int num, double randomness);
 int RAND_load_file(const char *file, long max_bytes);
