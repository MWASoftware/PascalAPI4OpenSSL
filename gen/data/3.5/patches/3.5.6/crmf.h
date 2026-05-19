--- /home/tony/SoftwareDev/external/openssl/openssl-3.5.6/include/openssl/crmf.h	2026-05-08 16:06:47.506980588 +0100
+++ crmf.tmp	2026-05-19 11:11:57.482310760 +0100
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
