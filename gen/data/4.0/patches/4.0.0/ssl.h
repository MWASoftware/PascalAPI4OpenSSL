--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/ssl.h	2026-05-09 15:59:00.771658452 +0100
+++ ssl.tmp	2026-05-19 11:14:11.174172986 +0100
@@ -241,13 +241,9 @@
 
 STACK_OF(SSL_CIPHER);
 
-/* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*/
-typedef struct srtp_protection_profile_st {
-    const char *name;
-    unsigned long id;
-} SRTP_PROTECTION_PROFILE;
 /* clang-format off */
 SKM_DEFINE_STACK_OF_INTERNAL(SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE)
+DEFINE_LHASH_OF(SSL_SESSION);
 #define sk_SRTP_PROTECTION_PROFILE_num(sk) OPENSSL_sk_num(ossl_check_const_SRTP_PROTECTION_PROFILE_sk_type(sk))
 #define sk_SRTP_PROTECTION_PROFILE_value(sk, idx) ((SRTP_PROTECTION_PROFILE *)OPENSSL_sk_value(ossl_check_const_SRTP_PROTECTION_PROFILE_sk_type(sk), (idx)))
 #define sk_SRTP_PROTECTION_PROFILE_new(cmp) ((STACK_OF(SRTP_PROTECTION_PROFILE) *)OPENSSL_sk_set_cmp_thunks(OPENSSL_sk_new(ossl_check_SRTP_PROTECTION_PROFILE_compfunc_type(cmp)), sk_SRTP_PROTECTION_PROFILE_cmpfunc_thunk))
@@ -275,6 +271,7 @@
 #define sk_SRTP_PROTECTION_PROFILE_set_cmp_func(sk, cmp) ((sk_SRTP_PROTECTION_PROFILE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_SRTP_PROTECTION_PROFILE_sk_type(sk), ossl_check_SRTP_PROTECTION_PROFILE_compfunc_type(cmp)))
 
 /* clang-format on */
+SKM_DEFINE_STACK_OF_INTERNAL(SSL_CIPHER, const SSL_CIPHER, SSL_CIPHER)
 
 typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data,
     int len, void *arg);
@@ -1024,7 +1021,6 @@
  * in VisualStudio 2015
  */
 /* clang-format off */
-SKM_DEFINE_STACK_OF_INTERNAL(SSL_CIPHER, const SSL_CIPHER, SSL_CIPHER)
 #define sk_SSL_CIPHER_num(sk) OPENSSL_sk_num(ossl_check_const_SSL_CIPHER_sk_type(sk))
 #define sk_SSL_CIPHER_value(sk, idx) ((const SSL_CIPHER *)OPENSSL_sk_value(ossl_check_const_SSL_CIPHER_sk_type(sk), (idx)))
 #define sk_SSL_CIPHER_new(cmp) ((STACK_OF(SSL_CIPHER) *)OPENSSL_sk_set_cmp_thunks(OPENSSL_sk_new(ossl_check_SSL_CIPHER_compfunc_type(cmp)), sk_SSL_CIPHER_cmpfunc_thunk))
@@ -1849,14 +1845,14 @@
     long length, OSSL_LIB_CTX *libctx,
     const char *propq);
 
-#ifdef OPENSSL_X509_H
+//#ifdef OPENSSL_X509_H
 __owur X509 *SSL_get0_peer_certificate(const SSL *s);
 __owur X509 *SSL_get1_peer_certificate(const SSL *s);
 /* Deprecated in 3.0.0 */
 #ifndef OPENSSL_NO_DEPRECATED_3_0
 #define SSL_get_peer_certificate SSL_get1_peer_certificate
 #endif
-#endif
+//#endif
 
 __owur STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s);
 
@@ -2653,9 +2649,9 @@
     ssl_ct_validation_cb callback,
     void *arg);
 #define SSL_disable_ct(s) \
-    ((void)SSL_set_validation_callback((s), NULL, NULL))
+    ((void)SSL_set_ct_validation_callback((s), NULL, NULL))
 #define SSL_CTX_disable_ct(ctx) \
-    ((void)SSL_CTX_set_validation_callback((ctx), NULL, NULL))
+    ((void)SSL_CTX_set_ct_validation_callback((ctx), NULL, NULL))
 
 /*
  * The validation type enumerates the available behaviours of the built-in SSL
