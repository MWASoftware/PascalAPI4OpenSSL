--- /home/tony/SoftwareDev/external/openssl/openssl-3.0.20/include/openssl/pkcs12.h	2026-05-04 13:52:25.940427401 +0100
+++ pkcs12.tmp	2026-05-19 11:14:40.835142419 +0100
@@ -45,10 +45,6 @@
 
 #define PKCS12_SALT_LEN 8
 
-/* It's not clear if these are actually needed... */
-#define PKCS12_key_gen PKCS12_key_gen_utf8
-#define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8
-
 /* MS key usage constants */
 
 #define KEY_EX 0x10
@@ -60,6 +56,10 @@
 
 typedef struct PKCS12_SAFEBAG_st PKCS12_SAFEBAG;
 
+/* It's not clear if these are actually needed... */
+#define PKCS12_key_gen PKCS12_key_gen_utf8
+#define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8
+
 /* clang-format off */
 SKM_DEFINE_STACK_OF_INTERNAL(PKCS12_SAFEBAG, PKCS12_SAFEBAG, PKCS12_SAFEBAG)
 #define sk_PKCS12_SAFEBAG_num(sk) OPENSSL_sk_num(ossl_check_const_PKCS12_SAFEBAG_sk_type(sk))
@@ -99,10 +99,6 @@
 
 #ifndef OPENSSL_NO_DEPRECATED_1_1_0
 
-#define M_PKCS12_bag_type PKCS12_bag_type
-#define M_PKCS12_cert_bag_type PKCS12_cert_bag_type
-#define M_PKCS12_crl_bag_type PKCS12_cert_bag_type
-
 #define PKCS12_certbag2x509 PKCS12_SAFEBAG_get1_cert
 #define PKCS12_certbag2scrl PKCS12_SAFEBAG_get1_crl
 #define PKCS12_bag_type PKCS12_SAFEBAG_get_nid
@@ -112,6 +108,10 @@
 #define PKCS12_MAKE_KEYBAG PKCS12_SAFEBAG_create0_p8inf
 #define PKCS12_MAKE_SHKEYBAG PKCS12_SAFEBAG_create_pkcs8_encrypt
 
+#define M_PKCS12_bag_type PKCS12_bag_type
+#define M_PKCS12_cert_bag_type PKCS12_cert_bag_type
+#define M_PKCS12_crl_bag_type PKCS12_cert_bag_type
+
 #endif
 #ifndef OPENSSL_NO_DEPRECATED_1_1_0
 OSSL_DEPRECATEDIN_1_1_0 ASN1_TYPE *PKCS12_get_attr(const PKCS12_SAFEBAG *bag,
