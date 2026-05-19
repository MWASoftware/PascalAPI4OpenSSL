procedure ERR_put_error(lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; file_: PAnsiChar; line: TOpenSSL_C_INT);
procedure X509err(const f,r : TOpenSSL_C_INT);
procedure SSLErr(func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT);

