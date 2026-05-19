{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License").

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.

    This file includes software copied from the Indy (Internet Direct) project, and which is offered
    under the dual-licensing agreement described on the Indy website. (https://www.indyproject.org/license/)
    }
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
const
  TLS_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}

function Load_Legacy_SSL_get_peer_certificate(const s: PSSL): PX509; cdecl; forward;
procedure Load_Legacy_SSL_load_error_strings; cdecl;  forward;
function Load_Legacy_SSL_library_init: TOpenSSL_C_INT; cdecl; forward;

var
  Legacy_SSLv2_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv2_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv2_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv3_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv3_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv3_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv23_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv23_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSLv23_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_1_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_1_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_1_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_2_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_2_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_TLSv1_2_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0}
  Legacy_SSL_get_peer_certificate: function (const s: PSSL): PX509; cdecl = Load_Legacy_SSL_get_peer_certificate; {removed 3.0.0}
  Legacy_SSL_load_error_strings: procedure ; cdecl = Load_Legacy_SSL_load_error_strings; {removed 1.1.0}
  Legacy_SSL_library_init: function : TOpenSSL_C_INT; cdecl = Load_Legacy_SSL_library_init; {removed 1.1.0}

  
function Load_Legacy_SSL_get_peer_certificate(const s: PSSL): PX509; cdecl;
begin
  Legacy_SSL_get_peer_certificate := LoadLibSSLFunction('SSL_get_peer_certificate');
  if not assigned(Legacy_SSL_get_peer_certificate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_peer_certificate');
  Result := Legacy_SSL_get_peer_certificate(s);
end;

procedure Load_Legacy_SSL_load_error_strings; cdecl;
begin
  Legacy_SSL_load_error_strings := LoadLibSSLFunction('SSL_load_error_strings');
  if not assigned(Legacy_SSL_load_error_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_load_error_strings');
  Legacy_SSL_load_error_strings();
end;

function Load_Legacy_SSL_library_init: TOpenSSL_C_INT; cdecl;
begin
  Legacy_SSL_library_init := LoadLibSSLFunction('SSL_library_init');
  if not assigned(Legacy_SSL_library_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_library_init');
  Result := Legacy_SSL_library_init();
end;


procedure Legacy_Load;
begin
  Legacy_SSLv2_method := LoadLibSSLFunction('SSLv2_method');
  Legacy_SSLv2_server_method := LoadLibSSLFunction('SSLv2_server_method');
  Legacy_SSLv2_client_method := LoadLibSSLFunction('SSLv2_client_method');
  Legacy_SSLv3_method := LoadLibSSLFunction('SSLv3_method');
  Legacy_SSLv3_server_method := LoadLibSSLFunction('SSLv3_server_method');
  Legacy_SSLv3_client_method := LoadLibSSLFunction('SSLv3_client_method');
  Legacy_SSLv23_method := LoadLibSSLFunction('SSLv23_method');
  Legacy_SSLv23_server_method := LoadLibSSLFunction('SSLv23_server_method');
  Legacy_SSLv23_client_method := LoadLibSSLFunction('SSLv23_client_method');
  Legacy_TLSv1_method := LoadLibSSLFunction('TLSv1_method');
  Legacy_TLSv1_server_method := LoadLibSSLFunction('TLSv1_server_method');
  Legacy_TLSv1_client_method := LoadLibSSLFunction('TLSv1_client_method');
  Legacy_TLSv1_1_method := LoadLibSSLFunction('TLSv1_1_method');
  Legacy_TLSv1_1_server_method := LoadLibSSLFunction('TLSv1_1_server_method');
  Legacy_TLSv1_1_client_method := LoadLibSSLFunction('TLSv1_1_client_method');
  Legacy_TLSv1_2_method := LoadLibSSLFunction('TLSv1_2_method');
  Legacy_TLSv1_2_server_method := LoadLibSSLFunction('TLSv1_2_server_method');
  Legacy_TLSv1_2_client_method := LoadLibSSLFunction('TLSv1_2_client_method');
 end;

procedure Legacy_Unload;
begin
  Legacy_SSLv2_method := nil;
  Legacy_SSLv2_server_method := nil;
  Legacy_SSLv2_client_method := nil;
  Legacy_SSLv3_method := nil;
  Legacy_SSLv3_server_method := nil;
  Legacy_SSLv3_client_method := nil;
  Legacy_SSLv23_method := nil;
  Legacy_SSLv23_server_method := nil;
  Legacy_SSLv23_client_method := nil;
  Legacy_TLSv1_method := nil;
  Legacy_TLSv1_server_method := nil;
  Legacy_TLSv1_client_method := nil;
  Legacy_TLSv1_1_method := nil;
  Legacy_TLSv1_1_server_method := nil;
  Legacy_TLSv1_1_client_method := nil;
  Legacy_TLSv1_2_method := nil;
  Legacy_TLSv1_2_server_method := nil;
  Legacy_TLSv1_2_client_method := nil;
end;

function LEGACY_SSL_get1_peer_certificate(const s: PSSL): PX509;
begin
  Result := Legacy_SSL_get_peer_certificate(s);
end;

function IsOpenSSL_SSLv2_Available : Boolean;
  begin
    Result := Assigned(Legacy_SSLv2_method) and
      Assigned(Legacy_SSLv2_server_method) and
      Assigned(Legacy_SSLv2_client_method);
  end;

  function IsOpenSSL_SSLv3_Available : Boolean;
  begin
    Result := Assigned(Legacy_SSLv3_method) and
      Assigned(Legacy_SSLv3_server_method) and
      Assigned(Legacy_SSLv3_client_method);
  end;

  function IsOpenSSL_SSLv23_Available : Boolean;
  begin
    Result := Assigned(Legacy_SSLv23_method) and
      Assigned(Legacy_SSLv23_server_method) and
      Assigned(Legacy_SSLv23_client_method);
  end;

  function IsOpenSSL_TLSv1_0_Available : Boolean;
  begin
    Result := Assigned(Legacy_TLSv1_method) and
      Assigned(Legacy_TLSv1_server_method) and
      Assigned(Legacy_TLSv1_client_method);
  end;

  function IsOpenSSL_TLSv1_1_Available : Boolean;
  begin
    Result := Assigned(Legacy_TLSv1_1_method) and
      Assigned(Legacy_TLSv1_1_server_method) and
      Assigned(Legacy_TLSv1_1_client_method);
  end;

  function IsOpenSSL_TLSv1_2_Available : Boolean;
  begin
     Result := Assigned(Legacy_TLSv1_2_method) and
      Assigned(Legacy_TLSv1_2_server_method) and
      Assigned(Legacy_TLSv1_2_client_method);
  end;

function HasTLS_method: boolean;
begin
  Result := (GetIOpenSSL = nil) or (TLS_method_introduced <= GetIOpenSSL.GetOpenSSLversion);
end;

function LEGACY_SSL_get_ex_data(const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer;
begin
  Result := SSL_get_app_data(ssl);
end;

function LEGACY_OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;
begin
  if opts and OPENSSL_INIT_LOAD_SSL_STRINGS <> 0 then
    Legacy_SSL_load_error_strings;
  Legacy_SSL_library_init;
  Result := OPENSSL_init_crypto(opts,settings);
end;

type
  PSTACK_OF_SSL_CIPHER = pointer;
  Plash_of_SSL_SESSION = pointer;
  SSL_CTX_stats = record
    sess_connect: TOpenSSL_C_INT;  // SSL new conn - started
    sess_connect_renegotiate: TOpenSSL_C_INT;  // SSL reneg - requested
    sess_connect_good: TOpenSSL_C_INT; // SSL new conne/reneg - finished
    sess_accept: TOpenSSL_C_INT;    // SSL new accept - started
    sess_accept_renegotiate: TOpenSSL_C_INT; // SSL reneg - requested
    sess_accept_good: TOpenSSL_C_INT;  // SSL accept/reneg - finished
    sess_miss: TOpenSSL_C_INT;  // session lookup misses
    sess_timeout: TOpenSSL_C_INT; // reuse attempt on timeouted session
    sess_cache_full: TOpenSSL_C_INT; // session removed due to full cache
    sess_hit: TOpenSSL_C_INT; // session reuse actually done
    sess_cb_hit: TOpenSSL_C_INT; // session-id that was not
                          // in the cache was
                          // passed back via the callback.  This
                          // indicates that the application is
                          // supplying session-id's from other
                          // processes - spooky :-)
  end;
  PSTACK_OF_COMP = pointer;
  PSSL_CTX_info_callback = pointer;
  PCERT = pointer;
  size_t = type integer;
  PSSL_CTEX_tlsext_servername_callback = pointer;
  Ptlsext_status_cb = pointer;
  Ptlsext_ticket_key_cb = pointer;
  Pssl3_buf_freelist_st = pointer;
  PSRP_CTX = ^SRP_CTX;
  SRP_CTX = record
	//* param for all the callbacks */
	  SRP_cb_arg : Pointer;
	//* set client Hello login callback */
    TLS_ext_srp_username_callback : function(para1 : PSSL; para2 : TOpenSSL_C_INT; para3 : Pointer) : TOpenSSL_C_INT cdecl;
	//int (*TLS_ext_srp_username_callback)(SSL *, int *, void *);
	//* set SRP N/g param callback for verification */
    SRP_verify_param_callback : function(para1 : PSSL; para2 : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*SRP_verify_param_callback)(SSL *, void *);
	//* set SRP client passwd callback */
    SRP_give_srp_client_pwd_callback : function(para1 : PSSL; para2 : Pointer) : PAnsiChar cdecl;
  //	char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *);
    login : PAnsiChar;
   	N, g, s, B, A : PBIGNUM;
   	_a, _b, v : PBIGNUM;
	  info : PAnsiChar;
	  strength : TOpenSSL_C_INT;
    srp_Mask : TOpenSSL_C_ULONG;
	end;
  PSTACK_OF_SRTP_PROTECTION_PROFILE = pointer;

  _PSSL_CTX = ^SSL_CTX;
  SSL_CTX = record
    method: PSSL_METHOD;
    cipher_list: PSTACK_OF_SSL_CIPHER;
    // same as above but sorted for lookup
    cipher_list_by_id: PSTACK_OF_SSL_CIPHER;
    cert_store: PX509_STORE;
    sessions: Plash_of_SSL_SESSION;
    // a set of SSL_SESSIONs
    // Most session-ids that will be cached, default is
    // SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
    session_cache_size: TOpenSSL_C_ULONG;
    session_cache_head: PSSL_SESSION;
    session_cache_tail: PSSL_SESSION;
    // This can have one of 2 values, ored together,
    // SSL_SESS_CACHE_CLIENT,
    // SSL_SESS_CACHE_SERVER,
    // Default is SSL_SESSION_CACHE_SERVER, which means only
    // SSL_accept which cache SSL_SESSIONS.
    session_cache_mode: TOpenSSL_C_INT;
    session_timeout: TOpenSSL_C_LONG;
    // If this callback is not null, it will be called each
    // time a session id is added to the cache.  If this function
    // returns 1, it means that the callback will do a
    // SSL_SESSION_free() when it has finished using it.  Otherwise,
    // on 0, it means the callback has finished with it.
    // If remove_session_cb is not null, it will be called when
    // a session-id is removed from the cache.  After the call,
    // OpenSSL will SSL_SESSION_free() it.
    new_session_cb: function (ssl : PSSL; sess: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
    remove_session_cb: procedure (ctx : PSSL_CTX; sess : PSSL_SESSION); cdecl;
    get_session_cb: function (ssl : PSSL; data : PByte; len: TOpenSSL_C_INT; copy : POpenSSL_C_INT) : PSSL_SESSION; cdecl;
    stats : SSL_CTX_stats;

    references: TOpenSSL_C_INT;
    // if defined, these override the X509_verify_cert() calls
    app_verify_callback: function (_para1 : PX509_STORE_CTX; _para2 : Pointer) : TOpenSSL_C_INT; cdecl;
    app_verify_arg: Pointer;
    // before OpenSSL 0.9.7, 'app_verify_arg' was ignored
    // ('app_verify_callback' was called with just one argument)
    // Default password callback.
    default_passwd_callback: Tpem_password_cb;
    // Default password callback user data.
    default_passwd_callback_userdata: Pointer;
    // get client cert callback
    client_cert_cb: function (SSL : PSSL; x509 : PPX509; pkey : PPEVP_PKEY) : TOpenSSL_C_INT; cdecl;
    // verify cookie callback
    app_gen_cookie_cb: function (ssl : PSSL; cookie : PByte; cookie_len : TOpenSSL_C_UINT) : TOpenSSL_C_INT; cdecl;
    app_verify_cookie_cb: Pointer;
    ex_data : TCRYPTO_EX_DATA;
    rsa_md5 : PEVP_MD; // For SSLv2 - name is 'ssl2-md5'
    md5: PEVP_MD; // For SSLv3/TLSv1 'ssl3-md5'
    sha1: PEVP_MD; // For SSLv3/TLSv1 'ssl3->sha1'
    extra_certs: Pstack_st_X509;
    comp_methods: PSTACK_OF_COMP; // stack of SSL_COMP, SSLv3/TLSv1
    // Default values used when no per-SSL value is defined follow
    info_callback: PSSL_CTX_info_callback; // used if SSL's info_callback is NULL
    // what we put in client cert requests
    client_CA : Pstack_st_X509_NAME;
    // Default values to use in SSL structures follow (these are copied by SSL_new)
    options : TOpenSSL_C_ULONG;
    mode : TOpenSSL_C_ULONG;
    max_cert_list : TOpenSSL_C_LONG;
    cert : PCERT;
    read_ahead : TOpenSSL_C_INT;
    // callback that allows applications to peek at protocol messages
    msg_callback : procedure (write_p, version, content_type : TOpenSSL_C_INT; const buf : Pointer; len : size_t; ssl : PSSL; arg : Pointer); cdecl;
    msg_callback_arg : Pointer;
    verify_mode : TOpenSSL_C_INT;
    sid_ctx_length : TOpenSSL_C_UINT;
    sid_ctx : array[0..SSL_MAX_SID_CTX_LENGTH - 1] of AnsiChar;
    default_verify_callback : function(ok : TOpenSSL_C_INT; ctx : PX509_STORE_CTX) : TOpenSSL_C_INT; cdecl; // called 'verify_callback' in the SSL
    // Default generate session ID callback.
    generate_session_id : PGEN_SESSION_CB;
    param : PX509_VERIFY_PARAM;
    {$IFDEF OMIT_THIS}
    purpose : TOpenSSL_C_INT;  // Purpose setting
    trust : TOpenSSL_C_INT;    // Trust setting
    {$ENDIF}

    quiet_shutdown : TOpenSSL_C_INT;
	//* Maximum amount of data to send in one fragment.
	// * actual record size can be more than this due to
	// * padding and MAC overheads.
	// */
	  max_send_fragment : TOpenSSL_C_UINT;
    {$IFNDEF OPENSSL_ENGINE}
	///* Engine to pass requests for client certs to
	// */
	  client_cert_engine : PENGINE;
    {$ENDIF}
    {$IFNDEF OPENSSL_NO_TLSEXT}
//* TLS extensions servername callback */
    tlsext_servername_callback : PSSL_CTEX_tlsext_servername_callback;
    tlsext_servername_arg : Pointer;
    //* RFC 4507 session ticket keys */
    tlsext_tick_key_name : array [0..(16-1)] of AnsiChar;
    tlsext_tick_hmac_key : array [0..(16-1)] of AnsiChar;
    tlsext_tick_aes_key : array [0..(16-1)] of AnsiChar;
	//* Callback to support customisation of ticket key setting */
 //	int (*tlsext_ticket_key_cb)(SSL *ssl,
 //					unsigned char *name, unsigned char *iv,
 //					EVP_CIPHER_CTX *ectx,
 //					HMAC_CTX *hctx, int enc);
    tlsext_ticket_key_cb : Ptlsext_ticket_key_cb;
	//* certificate status request info */
	//* Callback for status request */
	//int (*tlsext_status_cb)(SSL *ssl, void *arg);
    tlsext_status_cb : Ptlsext_status_cb;
	  tlsext_status_arg : Pointer;
    {$ENDIF}
	//* draft-rescorla-tls-opaque-prf-input-00.txt information */
     tlsext_opaque_prf_input_callback : function(para1 : PSSL; peerinput : Pointer; len : size_t; arg : Pointer ) : TOpenSSL_C_INT cdecl;
	//int (*tlsext_opaque_prf_input_callback)(SSL *, void *peerinput, size_t len, void *arg);
     tlsext_opaque_prf_input_callback_arg : Pointer;

{$ifndef OPENSSL_NO_PSK}
	   psk_identity_hint : PAnsiChar;
     psk_client_callback : function (ssl : PSSL; hint : PAnsiChar;
       identity : PAnsiChar; max_identity_len : TOpenSSL_C_UINT;
       psk : PAnsiChar; max_psk_len : TOpenSSL_C_UINT ) : TOpenSSL_C_UINT cdecl;
 //	unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
//		unsigned int max_identity_len, unsigned char *psk,
//		unsigned int max_psk_len);
     psk_server_callback : function (ssl : PSSL; identity, psk : PAnsiChar; max_psk_len : TOpenSSL_C_UINT) : TOpenSSL_C_UINT cdecl;
//	unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
//		unsigned char *psk, unsigned int max_psk_len);
{$endif}

{$ifndef OPENSSL_NO_BUF_FREELISTS}
	  freelist_max_len : TOpenSSL_C_UINT;
	  wbuf_freelist : Pssl3_buf_freelist_st;
	  rbuf_freelist : Pssl3_buf_freelist_st;
{$endif}
{$ifndef OPENSSL_NO_SRP}
	  srp_ctx : SRP_CTX; //* ctx for SRP authentication */
{$endif}

{$ifndef OPENSSL_NO_TLSEXT}
//# ifndef OPENSSL_NO_NEXTPROTONEG
	//* Next protocol negotiation information */
	//* (for experimental NPN extension). */

	//* For a server, this contains a callback function by which the set of
	// * advertised protocols can be provided. */
    next_protos_advertised_cb : function(s : PSSL; out but : PAnsiChar;
     out len : TOpenSSL_C_UINT; arg : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*next_protos_advertised_cb)(SSL *s, const unsigned char **buf,
//			                 unsigned int *len, void *arg);
	  next_protos_advertised_cb_arg : Pointer;
	//* For a client, this contains a callback function that selects the
	// * next protocol from the list provided by the server. */
    next_proto_select_cb : function(s : PSSL; out _out : PAnsiChar;
      outlen : PAnsiChar;
      _in : PAnsiChar;
      inlen : TOpenSSL_C_UINT;
      arg : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*next_proto_select_cb)(SSL *s, unsigned char **out,
//				    unsigned char *outlen,
//				    const unsigned char *in,
//				    unsigned int inlen,
//				    void *arg);
	  next_proto_select_cb_arg : Pointer;
//# endif
        //* SRTP profiles we are willing to do from RFC 5764 */
      srtp_profiles : PSTACK_OF_SRTP_PROTECTION_PROFILE;
{$endif}
  end;

const
  SSL_CTRL_OPTIONS = 32;
  SSL_CTRL_CLEAR_OPTIONS = 77;

function LEGACY_SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): Tpem_password_cb;
begin
  Result := _PSSL_CTX(ctx)^.default_passwd_callback;
end;

function LEGACY_SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer;
begin
  Result := _PSSL_CTX(ctx)^.default_passwd_callback_userdata;
end;

procedure LEGACY_SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: Tpem_password_cb);
begin
  _PSSL_CTX(ctx)^.default_passwd_callback := cb;
end;

procedure LEGACY_SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer);
begin
  _PSSL_CTX(ctx)^.default_passwd_callback_userdata := u;
end;

//* Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value,
// * they cannot be used to clear bits. */

function LEGACY_SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_LONG):TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, nil);
end;

function LEGACY_SSL_CTX_clear_options(ctx : PSSL_CTX; op : TOpenSSL_C_LONG):TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_OPTIONS,op,nil);
end;

function LEGACY_SSL_CTX_get_options(ctx: PSSL_CTX) : TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS,0,nil);
end;

function LEGACY_SSL_CTX_get_cert_store(const ctx: PSSL_CTX): PX509_STORE;
begin
  Result :=  _PSSL_CTX(ctx)^.cert_store;
end;

const
  SSL_MAX_KRB5_PRINCIPAL_LENGTH = 256;

type
   PSESS_CERT = pointer;
  _PSSL_SESSION = ^_SSL_SESSION;
  _SSL_SESSION = record
    ssl_version : TOpenSSL_C_INT; // what ssl version session info is being kept in here?
    // only really used in SSLv2
    key_arg_length: TOpenSSL_C_UINT;
    key_arg: Array[0..SSL_MAX_KEY_ARG_LENGTH-1] of Byte;
    master_key_length: TOpenSSL_C_INT;
    master_key: Array[0..SSL_MAX_MASTER_KEY_LENGTH-1] of Byte;
    // session_id - valid?
    session_id_length: TOpenSSL_C_UINT;
    session_id: Array[0..SSL_MAX_SSL_SESSION_ID_LENGTH-1] of Byte;
    // this is used to determine whether the session is being reused in
    // the appropriate context. It is up to the application to set this,
    // via SSL_new
    sid_ctx_length: TOpenSSL_C_UINT;
    sid_ctx: array[0..SSL_MAX_SID_CTX_LENGTH-1] of Byte;
    {$IFNDEF OPENSSL_NO_KRB5}
    krb5_client_princ_len: TOpenSSL_C_UINT;
    krb5_client_princ: array[0..SSL_MAX_KRB5_PRINCIPAL_LENGTH-1] of Byte;
    {$ENDIF}
{$ifndef OPENSSL_NO_PSK}
	  psk_identity_hint : PAnsiChar;
	  psk_identity : PAnsiChar;
{$endif}
    not_resumable: TOpenSSL_C_INT;
    // The cert is the certificate used to establish this connection
    sess_cert :  PSESS_CERT;

	//* This is the cert for the other end.
	// * On clients, it will be the same as sess_cert->peer_key->x509
	// * (the latter is not enough as sess_cert is not retained
	// * in the external representation of sessions, see ssl_asn1.c). */
	  peer : PX509;
	//* when app_verify_callback accepts a session where the peer's certificate
	// * is not ok, we must remember the error for session reuse: */
	  verify_result : TOpenSSL_C_LONG; //* only for servers */
	  references : TOpenSSL_C_INT;
	  timeout : TOpenSSL_C_LONG;
	  time : TOpenSSL_C_LONG;
	  compress_meth : TOpenSSL_C_UINT;	//* Need to lookup the method */

	  cipher : PSSL_CIPHER;
	  cipher_id : TOpenSSL_C_ULONG;	//* when ASN.1 loaded, this
					// * needs to be used to load
					// * the 'cipher' structure */
    ciphers : PSTACK_OF_SSL_CIPHER; //* shared ciphers? */
    ex_data : TCRYPTO_EX_DATA; // application specific data */
	//* These are used to make removal of session-ids more
	// * efficient and to implement a maximum cache size. */
	  prev, next : PSSL_SESSION;

    {$IFNDEF OPENSSL_NO_TLSEXT}
    tlsext_hostname : PAnsiChar;
      {$IFDEF OPENSSL_NO_EC}
	  tlsext_ecpointformatlist_length : size_t;
	  tlsext_ecpointformatlist : PAnsiChar; //* peer's list */
	  tlsext_ellipticcurvelist_length : size_t;
	  tlsext_ellipticcurvelist : PAnsiChar; //* peer's list */
      {$ENDIF} //* OPENSSL_NO_EC */

 //* RFC4507 info */
    tlsext_tick : PAnsiChar;//* Session ticket */
    tlsext_ticklen : size_t;//* Session ticket length */
    tlsext_tick_lifetime_hint : TOpenSSL_C_LONG;//* Session lifetime hint in seconds */
    {$ENDIF}
{$ifndef OPENSSL_NO_SRP}
	  srp_username : PAnsiChar;
{$endif}
  end;

function LEGACY_SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT;
begin
  Result := _PSSL_SESSION(s).ssl_version;
end;

threadvar SelectedMethod: TOpenSSL_Version;

procedure OpenSSL_SetMethod(aMethod: TOpenSSL_Version);
begin
  SelectedMethod := aMethod;
end;

{TLS_Method was introduced in 1.1.0. For earlier versions of OpenSSL we need
 to select the appropriate method to negotiate the session}

function LEGACY_TLS_method: PSSL_METHOD;
begin
  Result := nil;
  case SelectedMethod of
    SSLvSSLv2:
        if Assigned(Legacy_SSLv2_method) then
          Result := Legacy_SSLv2_method();

    SSLvSSLv23:
          if Assigned(Legacy_SSLv23_client_method) then
            Result := Legacy_SSLv23_client_method();

    SSLvSSLv3:
        if Assigned(Legacy_SSLv3_method) then
          Result := Legacy_SSLv3_method();

    SSLvTLSv1:
        if Assigned(Legacy_TLSv1_method) then
          Result := Legacy_TLSv1_method();

    SSLvTLSv1_1:
        if Assigned(Legacy_TLSv1_1_method) then
          Result := Legacy_TLSv1_1_method()
        else
        if Assigned(Legacy_TLSv1_method) then
          Result := Legacy_TLSv1_method();

    //SSLvTLSv1_2:
    else
        if Assigned(Legacy_TLSv1_2_method) then
          Result := Legacy_TLSv1_2_method()
        else
        if Assigned(Legacy_TLSv1_method) then
          Result := Legacy_TLSv1_method();
  end;
end;

function LEGACY_TLS_server_method: PSSL_METHOD;
begin
  Result := nil;
  case SelectedMethod of
    SSLvSSLv2:
          if Assigned(Legacy_SSLv2_server_method) then
            Result := Legacy_SSLv2_server_method();

    SSLvSSLv23:
          if Assigned(Legacy_SSLv23_server_method) then
            Result := Legacy_SSLv23_server_method();

    SSLvSSLv3:
          if Assigned(Legacy_SSLv3_server_method) then
            Result := Legacy_SSLv3_server_method();

    SSLvTLSv1:
      if Assigned(Legacy_TLSv1_server_method) then
        Result := Legacy_TLSv1_server_method();

    SSLvTLSv1_1:
          if Assigned(Legacy_TLSv1_1_server_method) then
            Result := Legacy_TLSv1_1_server_method()
          else
          if Assigned(Legacy_TLSv1_server_method) then
            Result := Legacy_TLSv1_server_method();

    //SSLvTLSv1_2:
    else
          if Assigned(Legacy_TLSv1_2_server_method) then
            Result := Legacy_TLSv1_2_server_method()
          else
          if Assigned(Legacy_TLSv1_server_method) then
            Result := Legacy_TLSv1_server_method();
  end;
end;

function LEGACY_TLS_client_method: PSSL_METHOD;
begin
  Result := nil;
  case SelectedMethod of
    SSLvSSLv2:
          if Assigned(Legacy_SSLv2_client_method) then
            Result := Legacy_SSLv2_client_method();

    SSLvSSLv23:
          if Assigned(Legacy_SSLv23_client_method) then
            Result := Legacy_SSLv23_client_method();

    SSLvSSLv3:
          if Assigned(Legacy_SSLv3_client_method) then
            Result := Legacy_SSLv3_client_method();

    SSLvTLSv1:
      if Assigned(Legacy_TLSv1_client_method) then
        Result := Legacy_TLSv1_client_method();

    SSLvTLSv1_1:
          if Assigned(Legacy_TLSv1_1_client_method) then
            Result := Legacy_TLSv1_1_client_method()
          else
          if Assigned(Legacy_TLSv1_client_method) then
            Result := Legacy_TLSv1_client_method();

//    SSLvTLSv1_2:
    else
          if Assigned(Legacy_TLSv1_2_client_method) then
            Result := Legacy_TLSv1_2_client_method()
          else
          if Assigned(Legacy_TLSv1_client_method) then
            Result := Legacy_TLSv1_client_method();
  end;
end;

function LEGACY_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT;
begin
  Result := SSL_CTX_use_certificate_file(ctx, file_, SSL_FILETYPE_PEM);
end;

function LEGACY_SSL_new_session_ticket(s: PSSL):TOpenSSL_C_INT;
begin
// no op
  Result := 0;
end;

procedure LegacySupport_Initialization;
begin
  Register_SSLLoader(@Legacy_Load);
  Register_SSLUnLoader(@Legacy_Unload);
end;


{$endif}
{$endif}
