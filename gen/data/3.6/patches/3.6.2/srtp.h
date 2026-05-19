--- /home/tony/SoftwareDev/external/openssl/openssl-3.6.2/include/openssl/srtp.h	2026-04-07 13:17:57.000000000 +0100
+++ srtp.tmp	2026-05-19 11:12:35.749271325 +0100
@@ -39,6 +39,15 @@
 #define SRTP_AEAD_AES_128_GCM 0x0007
 #define SRTP_AEAD_AES_256_GCM 0x0008
 
+//Moved for ssl.h
+/* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*/
+typedef struct srtp_protection_profile_st {
+    const char *name;
+    unsigned long id;
+} SRTP_PROTECTION_PROFILE;
+SKM_DEFINE_STACK_OF_INTERNAL(SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE)
+
+
 /* DOUBLE AEAD SRTP protection profiles from RFC 8723 */
 #define SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM 0x0009
 #define SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM 0x000A
