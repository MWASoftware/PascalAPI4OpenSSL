--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.6/include/openssl/bio.h	2026-05-08 16:06:47.079980193 +0100
+++ bio.tmp	2026-05-19 11:11:57.460310782 +0100
@@ -333,7 +333,7 @@
 int BIO_method_type(const BIO *b);
 
 typedef int BIO_info_cb(BIO *, int, int);
-typedef BIO_info_cb bio_info_cb; /* backward compatibility */
+//typedef BIO_info_cb bio_info_cb; /* backward compatibility */
 
 /* clang-format off */
 SKM_DEFINE_STACK_OF_INTERNAL(BIO, BIO, BIO)
@@ -547,12 +547,6 @@
 #define BIO_get_accept_ip_family(b) BIO_ctrl(b, BIO_C_GET_ACCEPT, 4, NULL)
 #define BIO_set_tfo_accept(b, n) BIO_ctrl(b, BIO_C_SET_ACCEPT, 5, (n) ? (void *)"a" : NULL)
 
-/* Aliases kept for backward compatibility */
-#define BIO_BIND_NORMAL 0
-#define BIO_BIND_REUSEADDR BIO_SOCK_REUSEADDR
-#define BIO_BIND_REUSEADDR_IF_UNUSED BIO_SOCK_REUSEADDR
-#define BIO_set_bind_mode(b, mode) BIO_ctrl(b, BIO_C_SET_BIND_MODE, mode, NULL)
-#define BIO_get_bind_mode(b) BIO_ctrl(b, BIO_C_GET_BIND_MODE, 0, NULL)
 #endif /* OPENSSL_NO_SOCK */
 
 #define BIO_do_connect(b) BIO_do_handshake(b)
@@ -959,6 +953,15 @@
 #else
 #define ossl_bio__printf__ __printf__
 #endif
+
+#ifndef OPENSSL_NO_SOCK
+/* Aliases kept for backward compatibility */
+#define BIO_BIND_NORMAL 0
+#define BIO_BIND_REUSEADDR BIO_SOCK_REUSEADDR
+#define BIO_BIND_REUSEADDR_IF_UNUSED BIO_SOCK_REUSEADDR
+#define BIO_set_bind_mode(b, mode) BIO_ctrl(b, BIO_C_SET_BIND_MODE, mode, NULL)
+#define BIO_get_bind_mode(b) BIO_ctrl(b, BIO_C_GET_BIND_MODE, 0, NULL)
+#endif
 #endif
 #endif
 int BIO_printf(BIO *bio, const char *format, ...)
