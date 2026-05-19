--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/x509v3.h	2026-05-16 11:56:04.677334784 +0100
+++ x509v3.tmp	2026-05-19 11:12:35.778271295 +0100
@@ -91,12 +91,12 @@
 } X509V3_CONF_METHOD;
 
 /* Context specific info for producing X509 v3 extensions*/
-struct v3_ext_ctx {
 #define X509V3_CTX_TEST 0x1
 #ifndef OPENSSL_NO_DEPRECATED_3_0
 #define CTX_TEST X509V3_CTX_TEST
 #endif
 #define X509V3_CTX_REPLACE 0x2
+struct v3_ext_ctx {
     int flags;
     X509 *issuer_cert;
     X509 *subject_cert;
@@ -1383,6 +1383,9 @@
 typedef struct ProfessionInfo_st PROFESSION_INFO;
 typedef struct Admissions_st ADMISSIONS;
 typedef struct AdmissionSyntax_st ADMISSION_SYNTAX;
+typedef STACK_OF(USERNOTICE) OSSL_USER_NOTICE_SYNTAX;
+typedef STACK_OF(PROFESSION_INFO) PROFESSION_INFOS;
+typedef STACK_OF(X509_ATTRIBUTE) OSSL_ATTRIBUTES_SYNTAX;
 DECLARE_ASN1_FUNCTIONS(NAMING_AUTHORITY)
 DECLARE_ASN1_FUNCTIONS(PROFESSION_INFO)
 DECLARE_ASN1_FUNCTIONS(ADMISSIONS)
@@ -1442,7 +1445,7 @@
 #define sk_ADMISSIONS_set_cmp_func(sk, cmp) ((sk_ADMISSIONS_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_compfunc_type(cmp)))
 
 /* clang-format on */
-typedef STACK_OF(PROFESSION_INFO) PROFESSION_INFOS;
+
 
 const ASN1_OBJECT *NAMING_AUTHORITY_get0_authorityId(
     const NAMING_AUTHORITY *n);
@@ -1494,10 +1497,8 @@
 
 int OSSL_GENERAL_NAMES_print(BIO *out, GENERAL_NAMES *gens, int indent);
 
-typedef STACK_OF(X509_ATTRIBUTE) OSSL_ATTRIBUTES_SYNTAX;
 DECLARE_ASN1_FUNCTIONS(OSSL_ATTRIBUTES_SYNTAX)
 
-typedef STACK_OF(USERNOTICE) OSSL_USER_NOTICE_SYNTAX;
 DECLARE_ASN1_FUNCTIONS(OSSL_USER_NOTICE_SYNTAX)
 
 /* clang-format off */
