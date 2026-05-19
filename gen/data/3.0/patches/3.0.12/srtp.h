41a42,50
> //Moved for ssl.h
> /* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*/
> typedef struct srtp_protection_profile_st {
>     const char *name;
>     unsigned long id;
> } SRTP_PROTECTION_PROFILE;
> SKM_DEFINE_STACK_OF_INTERNAL(SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE)
> 
> 
