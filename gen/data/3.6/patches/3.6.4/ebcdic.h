--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.4/include/openssl/ebcdic.h	2026-08-25 12:48:34.000000000 +0100
+++ ebcdic.tmp	2026-09-16 15:16:05.781222896 +0100
@@ -23,10 +23,10 @@
 #endif
 
 /* Avoid name clashes with other applications */
-#define os_toascii _openssl_os_toascii
-#define os_toebcdic _openssl_os_toebcdic
-#define ebcdic2ascii _openssl_ebcdic2ascii
-#define ascii2ebcdic _openssl_ascii2ebcdic
+//#define os_toascii _openssl_os_toascii
+//#define os_toebcdic _openssl_os_toebcdic
+//#define ebcdic2ascii _openssl_ebcdic2ascii
+//#define ascii2ebcdic _openssl_ascii2ebcdic
 
 extern const unsigned char os_toascii[256];
 extern const unsigned char os_toebcdic[256];
