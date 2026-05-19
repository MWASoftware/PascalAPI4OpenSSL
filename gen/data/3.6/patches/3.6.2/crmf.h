--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/crmf.h	2026-05-16 11:56:03.410333708 +0100
+++ crmf.tmp	2026-05-19 11:12:35.692271383 +0100
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
