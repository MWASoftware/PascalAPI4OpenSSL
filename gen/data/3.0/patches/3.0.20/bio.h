--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/bio.h	2026-05-04 13:52:25.088425305 +0100
+++ bio.tmp	2026-05-19 11:14:40.798142457 +0100
@@ -301,7 +301,7 @@
 int BIO_method_type(const BIO *b);
 
 typedef int BIO_info_cb(BIO *, int, int);
-typedef BIO_info_cb bio_info_cb; /* backward compatibility */
+//typedef BIO_info_cb bio_info_cb; /* backward compatibility */
 
 /* clang-format off */
 SKM_DEFINE_STACK_OF_INTERNAL(BIO, BIO, BIO)
@@ -473,12 +473,6 @@
 #define BIO_set_accept_ip_family(b, f) BIO_int_ctrl(b, BIO_C_SET_ACCEPT, 4, f)
 #define BIO_get_accept_ip_family(b) BIO_ctrl(b, BIO_C_GET_ACCEPT, 4, NULL)
 
-/* Aliases kept for backward compatibility */
-#define BIO_BIND_NORMAL 0
-#define BIO_BIND_REUSEADDR BIO_SOCK_REUSEADDR
-#define BIO_BIND_REUSEADDR_IF_UNUSED BIO_SOCK_REUSEADDR
-#define BIO_set_bind_mode(b, mode) BIO_ctrl(b, BIO_C_SET_BIND_MODE, mode, NULL)
-#define BIO_get_bind_mode(b) BIO_ctrl(b, BIO_C_GET_BIND_MODE, 0, NULL)
 #endif /* OPENSSL_NO_SOCK */
 
 #define BIO_do_connect(b) BIO_do_handshake(b)
@@ -886,6 +880,15 @@
     long (*callback_ctrl)(BIO *, int,
         BIO_info_cb *));
 
+#ifndef OPENSSL_NO_SOCK
+/* Aliases kept for backward compatibility */
+#define BIO_BIND_NORMAL 0
+#define BIO_BIND_REUSEADDR BIO_SOCK_REUSEADDR
+#define BIO_BIND_REUSEADDR_IF_UNUSED BIO_SOCK_REUSEADDR
+#define BIO_set_bind_mode(b, mode) BIO_ctrl(b, BIO_C_SET_BIND_MODE, mode, NULL)
+#define BIO_get_bind_mode(b) BIO_ctrl(b, BIO_C_GET_BIND_MODE, 0, NULL)
+#endif
+
 #ifdef __cplusplus
 }
 #endif
