302c302
< typedef BIO_info_cb bio_info_cb;  /* backward compatibility */
---
> //typedef BIO_info_cb bio_info_cb;  /* backward compatibility */
473,478d472
< /* Aliases kept for backward compatibility */
< #  define BIO_BIND_NORMAL                 0
< #  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR
< #  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR
< #  define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)
< #  define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)
883a878,885
> # ifndef OPENSSL_NO_SOCK
> /* Aliases kept for backward compatibility */
> #  define BIO_BIND_NORMAL                 0
> #  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR
> #  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR
> #  define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)
> #  define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)
> #endif
