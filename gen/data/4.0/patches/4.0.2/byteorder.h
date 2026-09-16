--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.2/include/openssl/byteorder.h	2026-08-25 12:38:35.000000000 +0100
+++ byteorder.tmp	2026-09-16 14:55:48.070326692 +0100
@@ -20,6 +20,7 @@
  * swapping is required, or a suitable swap instruction is available.
  */
 
+/*
 #if defined(_MSC_VER) && _MSC_VER >= 1300
 #include <stdlib.h>
 #pragma intrinsic(_byteswap_ushort)
@@ -90,6 +91,7 @@
 #define OSSL_LE64TOH(x) OSSwapLittleToHostInt64(x)
 
 #endif
+*/
 
 static ossl_inline ossl_unused unsigned char *
 OPENSSL_store_u16_le(unsigned char *out, uint16_t val)
