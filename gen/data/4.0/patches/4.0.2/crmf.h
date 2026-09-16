--- /home/tony/SoftwareDev/external/openssl/openssl-4.0.2/include/openssl/crmf.h	2026-09-16 14:39:15.156411290 +0100
+++ crmf.tmp	2026-09-16 14:55:48.088326690 +0100
@@ -272,6 +272,15 @@
 OSSL_CRMF_ENCRYPTEDKEY *OSSL_CRMF_ENCRYPTEDKEY_init_envdata(CMS_EnvelopedData *envdata);
 #endif
 
+//Moved from cmp.h
+#define OSSL_CMP_ATAV_free OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free
+#define stack_st_OSSL_CMP_ATAV stack_st_OSSL_CRMF_ATTRIBUTETYPEANDVALUE
+#define sk_OSSL_CMP_ATAV_num sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_num
+#define sk_OSSL_CMP_ATAV_value sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_value
+#define sk_OSSL_CMP_ATAV_push sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_push
+#define sk_OSSL_CMP_ATAV_pop_free sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_pop_free
+
+
 #ifdef __cplusplus
 }
 #endif
