--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/rand.h	2026-04-07 13:17:57.000000000 +0100
+++ rand.tmp	2026-05-19 11:12:35.733271341 +0100
@@ -96,7 +96,7 @@
 void RAND_keep_random_devices_open(int keep);
 
 #if defined(__ANDROID__) && defined(__NDK_FPABI__)
-__NDK_FPABI__ /* __attribute__((pcs("aapcs"))) on ARM */
+//__NDK_FPABI__ /* __attribute__((pcs("aapcs"))) on ARM */
 #endif
     void RAND_add(const void *buf, int num, double randomness);
 int RAND_load_file(const char *file, long max_bytes);
