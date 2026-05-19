--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.0/include/openssl/pkcs12.h	2026-05-09 15:59:00.477658172 +0100
+++ pkcs12.tmp	2026-05-19 11:14:11.138173023 +0100
@@ -55,10 +55,6 @@
 #define PKCS12_SALT_LEN 16
 #endif
 
-/* It's not clear if these are actually needed... */
-#define PKCS12_key_gen PKCS12_key_gen_utf8
-#define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8
-
 /* MS key usage constants */
 
 #define KEY_EX 0x10
@@ -70,6 +66,10 @@
 
 typedef struct PKCS12_SAFEBAG_st PKCS12_SAFEBAG;
 
+/* It's not clear if these are actually needed... */
+#define PKCS12_key_gen PKCS12_key_gen_utf8
+#define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8
+
 /* clang-format off */
 SKM_DEFINE_STACK_OF_INTERNAL(PKCS12_SAFEBAG, PKCS12_SAFEBAG, PKCS12_SAFEBAG)
 #define sk_PKCS12_SAFEBAG_num(sk) OPENSSL_sk_num(ossl_check_const_PKCS12_SAFEBAG_sk_type(sk))
@@ -109,10 +109,6 @@
 
 #ifndef OPENSSL_NO_DEPRECATED_1_1_0
 
-#define M_PKCS12_bag_type PKCS12_bag_type
-#define M_PKCS12_cert_bag_type PKCS12_cert_bag_type
-#define M_PKCS12_crl_bag_type PKCS12_cert_bag_type
-
 #define PKCS12_certbag2x509 PKCS12_SAFEBAG_get1_cert
 #define PKCS12_certbag2scrl PKCS12_SAFEBAG_get1_crl
 #define PKCS12_bag_type PKCS12_SAFEBAG_get_nid
@@ -122,6 +118,10 @@
 #define PKCS12_MAKE_KEYBAG PKCS12_SAFEBAG_create0_p8inf
 #define PKCS12_MAKE_SHKEYBAG PKCS12_SAFEBAG_create_pkcs8_encrypt
 
+#define M_PKCS12_bag_type PKCS12_bag_type
+#define M_PKCS12_cert_bag_type PKCS12_cert_bag_type
+#define M_PKCS12_crl_bag_type PKCS12_cert_bag_type
+
 #endif
 #ifndef OPENSSL_NO_DEPRECATED_1_1_0
 OSSL_DEPRECATEDIN_1_1_0 const ASN1_TYPE *PKCS12_get_attr(const PKCS12_SAFEBAG *bag,
