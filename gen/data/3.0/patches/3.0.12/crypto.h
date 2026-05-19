59,78d58
< # ifndef OPENSSL_NO_DEPRECATED_1_1_0
< #  define SSLeay                  OpenSSL_version_num
< #  define SSLeay_version          OpenSSL_version
< #  define SSLEAY_VERSION_NUMBER   OPENSSL_VERSION_NUMBER
< #  define SSLEAY_VERSION          OPENSSL_VERSION
< #  define SSLEAY_CFLAGS           OPENSSL_CFLAGS
< #  define SSLEAY_BUILT_ON         OPENSSL_BUILT_ON
< #  define SSLEAY_PLATFORM         OPENSSL_PLATFORM
< #  define SSLEAY_DIR              OPENSSL_DIR
< 
< /*
<  * Old type for allocating dynamic locks. No longer used. Use the new thread
<  * API instead.
<  */
< typedef struct {
<     int dummy;
< } CRYPTO_dynlock;
< 
< # endif /* OPENSSL_NO_DEPRECATED_1_1_0 */
< 
553a534,555
> 
> # ifndef OPENSSL_NO_DEPRECATED_1_1_0
> #  define SSLeay                  OpenSSL_version_num
> #  define SSLeay_version          OpenSSL_version
> #  define SSLEAY_VERSION_NUMBER   OPENSSL_VERSION_NUMBER
> #  define SSLEAY_VERSION          OPENSSL_VERSION
> #  define SSLEAY_CFLAGS           OPENSSL_CFLAGS
> #  define SSLEAY_BUILT_ON         OPENSSL_BUILT_ON
> #  define SSLEAY_PLATFORM         OPENSSL_PLATFORM
> #  define SSLEAY_DIR              OPENSSL_DIR
> 
> /*
>  * Old type for allocating dynamic locks. No longer used. Use the new thread
>  * API instead.
>  */
> typedef struct {
>     int dummy;
> } CRYPTO_dynlock;
> 
> # endif /* OPENSSL_NO_DEPRECATED_1_1_0 */
> 
> 
