209c209
< #   define OSSL_SSIZE_MAX ((ssize_t)(SIZE_MAX>>1))
---
> #   define OSSL_SSIZE_MAX SIZE_MAX>>1)
231c231
< # elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || \
---
> # elif  __STDC_VERSION__ >= 199901L) || \
