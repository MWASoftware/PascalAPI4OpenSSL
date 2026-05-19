262c262
< static ossl_unused ossl_inline int ERR_FATAL_ERROR(unsigned long errcode)
---
> static ossl_unused ossl_inline bool ERR_FATAL_ERROR(unsigned long errcode)
267c267
< static ossl_unused ossl_inline int ERR_COMMON_ERROR(unsigned long errcode)
---
> static ossl_unused ossl_inline bool ERR_COMMON_ERROR(unsigned long errcode)
