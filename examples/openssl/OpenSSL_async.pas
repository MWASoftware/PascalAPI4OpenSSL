(* This unit was generated from the source file async.h2pas 
It should not be modified directly. All changes should be made to async.h2pas
and this file regenerated *)

{$i OpenSSLDefines.inc}

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


unit OpenSSL_async;


interface

// Headers for OpenSSL 1.1.1
// async.h


uses
  OpenSSLAPI;

const
  ASYNC_ERR = 0;
  ASYNC_NO_JOBS = 0;
  ASYNC_PAUSE = 2;
  ASYNC_FINISH = 3;

type
  async_job_st = type Pointer;
  ASYNC_JOB = async_job_st;
  PASYNC_JOB = ^ASYNC_JOB;
  PPASYNC_JOB = ^PASYNC_JOB;
  
  async_wait_ctx_st = type Pointer;
  ASYNC_WAIT_CTX = async_wait_ctx_st;
  PASYNC_WAIT_CTX = ^ASYNC_WAIT_CTX;
  
  OSSL_ASYNC_FD = type TOpenSSL_C_INT;
  POSSL_ASYNC_FD = ^OSSL_ASYNC_FD;

  ASYNC_WAIT_CTX_set_wait_fd_cleanup = procedure(v1: PASYNC_WAIT_CTX;
    const v2: Pointer; v3: OSSL_ASYNC_FD; v4: Pointer);
  ASYNC_start_job_cb = function(v1: Pointer): TOpenSSL_C_INT;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ASYNC_init_thread}
{$EXTERNALSYM ASYNC_cleanup_thread}
{$EXTERNALSYM ASYNC_WAIT_CTX_new}
{$EXTERNALSYM ASYNC_WAIT_CTX_free}
{$EXTERNALSYM ASYNC_WAIT_CTX_set_wait_fd}
{$EXTERNALSYM ASYNC_WAIT_CTX_get_fd}
{$EXTERNALSYM ASYNC_WAIT_CTX_get_all_fds}
{$EXTERNALSYM ASYNC_WAIT_CTX_get_changed_fds}
{$EXTERNALSYM ASYNC_WAIT_CTX_clear_fd}
{$EXTERNALSYM ASYNC_is_capable}
{$EXTERNALSYM ASYNC_start_job}
{$EXTERNALSYM ASYNC_pause_job}
{$EXTERNALSYM ASYNC_get_current_job}
{$EXTERNALSYM ASYNC_get_wait_ctx}
{$EXTERNALSYM ASYNC_block_pause}
{$EXTERNALSYM ASYNC_unblock_pause}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASYNC_cleanup_thread; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl; external CLibCrypto;
procedure ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_is_capable: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: ASYNC_start_job_cb; args: Pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_pause_job: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_get_current_job: PASYNC_JOB; cdecl; external CLibCrypto;
function ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl; external CLibCrypto;
procedure ASYNC_block_pause; cdecl; external CLibCrypto;
procedure ASYNC_unblock_pause; cdecl; external CLibCrypto;

{$ELSE}
var
  ASYNC_init_thread: function (max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  ASYNC_cleanup_thread: procedure ; cdecl = nil;
  ASYNC_WAIT_CTX_new: function : PASYNC_WAIT_CTX; cdecl = nil;
  ASYNC_WAIT_CTX_free: procedure (ctx: PASYNC_WAIT_CTX); cdecl = nil;
  ASYNC_WAIT_CTX_set_wait_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TOpenSSL_C_INT; cdecl = nil;
  ASYNC_WAIT_CTX_get_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TOpenSSL_C_INT; cdecl = nil;
  ASYNC_WAIT_CTX_get_all_fds: function (ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  ASYNC_WAIT_CTX_get_changed_fds: function (ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  ASYNC_WAIT_CTX_clear_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer): TOpenSSL_C_INT; cdecl = nil;
  ASYNC_is_capable: function : TOpenSSL_C_INT; cdecl = nil;
  ASYNC_start_job: function (job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: ASYNC_start_job_cb; args: Pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  ASYNC_pause_job: function : TOpenSSL_C_INT; cdecl = nil;
  ASYNC_get_current_job: function : PASYNC_JOB; cdecl = nil;
  ASYNC_get_wait_ctx: function (job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl = nil;
  ASYNC_block_pause: procedure ; cdecl = nil;
  ASYNC_unblock_pause: procedure ; cdecl = nil;
{$ENDIF}
const
  ASYNC_init_thread_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_cleanup_thread_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_set_wait_fd_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_fd_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_all_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_changed_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_clear_fd_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_is_capable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_start_job_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_pause_job_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_get_current_job_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_get_wait_ctx_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_block_pause_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_unblock_pause_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_init_thread');
end;

procedure ERROR_ASYNC_cleanup_thread; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_cleanup_thread');
end;

function ERROR_ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_new');
end;

procedure ERROR_ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_free');
end;

function ERROR_ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_set_wait_fd');
end;

function ERROR_ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_fd');
end;

function ERROR_ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_all_fds');
end;

function ERROR_ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_changed_fds');
end;

function ERROR_ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_clear_fd');
end;

function ERROR_ASYNC_is_capable: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_is_capable');
end;

function ERROR_ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: ASYNC_start_job_cb; args: Pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_start_job');
end;

function ERROR_ASYNC_pause_job: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_pause_job');
end;

function ERROR_ASYNC_get_current_job: PASYNC_JOB; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_get_current_job');
end;

function ERROR_ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_get_wait_ctx');
end;

procedure ERROR_ASYNC_block_pause; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_block_pause');
end;

procedure ERROR_ASYNC_unblock_pause; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_unblock_pause');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  ASYNC_init_thread := LoadLibCryptoFunction('ASYNC_init_thread');
  FuncLoadError := not assigned(ASYNC_init_thread);
  if FuncLoadError then
  begin
    ASYNC_init_thread :=  @ERROR_ASYNC_init_thread;
  end;

  ASYNC_cleanup_thread := LoadLibCryptoFunction('ASYNC_cleanup_thread');
  FuncLoadError := not assigned(ASYNC_cleanup_thread);
  if FuncLoadError then
  begin
    ASYNC_cleanup_thread :=  @ERROR_ASYNC_cleanup_thread;
  end;

  ASYNC_WAIT_CTX_new := LoadLibCryptoFunction('ASYNC_WAIT_CTX_new');
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_new);
  if FuncLoadError then
  begin
    ASYNC_WAIT_CTX_new :=  @ERROR_ASYNC_WAIT_CTX_new;
  end;

  ASYNC_WAIT_CTX_free := LoadLibCryptoFunction('ASYNC_WAIT_CTX_free');
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_free);
  if FuncLoadError then
  begin
    ASYNC_WAIT_CTX_free :=  @ERROR_ASYNC_WAIT_CTX_free;
  end;

  ASYNC_WAIT_CTX_set_wait_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_set_wait_fd');
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_set_wait_fd);
  if FuncLoadError then
  begin
    ASYNC_WAIT_CTX_set_wait_fd :=  @ERROR_ASYNC_WAIT_CTX_set_wait_fd;
  end;

  ASYNC_WAIT_CTX_get_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_fd');
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_fd);
  if FuncLoadError then
  begin
    ASYNC_WAIT_CTX_get_fd :=  @ERROR_ASYNC_WAIT_CTX_get_fd;
  end;

  ASYNC_WAIT_CTX_get_all_fds := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_all_fds');
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_all_fds);
  if FuncLoadError then
  begin
    ASYNC_WAIT_CTX_get_all_fds :=  @ERROR_ASYNC_WAIT_CTX_get_all_fds;
  end;

  ASYNC_WAIT_CTX_get_changed_fds := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_changed_fds');
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_changed_fds);
  if FuncLoadError then
  begin
    ASYNC_WAIT_CTX_get_changed_fds :=  @ERROR_ASYNC_WAIT_CTX_get_changed_fds;
  end;

  ASYNC_WAIT_CTX_clear_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_clear_fd');
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_clear_fd);
  if FuncLoadError then
  begin
    ASYNC_WAIT_CTX_clear_fd :=  @ERROR_ASYNC_WAIT_CTX_clear_fd;
  end;

  ASYNC_is_capable := LoadLibCryptoFunction('ASYNC_is_capable');
  FuncLoadError := not assigned(ASYNC_is_capable);
  if FuncLoadError then
  begin
    ASYNC_is_capable :=  @ERROR_ASYNC_is_capable;
  end;

  ASYNC_start_job := LoadLibCryptoFunction('ASYNC_start_job');
  FuncLoadError := not assigned(ASYNC_start_job);
  if FuncLoadError then
  begin
    ASYNC_start_job :=  @ERROR_ASYNC_start_job;
  end;

  ASYNC_pause_job := LoadLibCryptoFunction('ASYNC_pause_job');
  FuncLoadError := not assigned(ASYNC_pause_job);
  if FuncLoadError then
  begin
    ASYNC_pause_job :=  @ERROR_ASYNC_pause_job;
  end;

  ASYNC_get_current_job := LoadLibCryptoFunction('ASYNC_get_current_job');
  FuncLoadError := not assigned(ASYNC_get_current_job);
  if FuncLoadError then
  begin
    ASYNC_get_current_job :=  @ERROR_ASYNC_get_current_job;
  end;

  ASYNC_get_wait_ctx := LoadLibCryptoFunction('ASYNC_get_wait_ctx');
  FuncLoadError := not assigned(ASYNC_get_wait_ctx);
  if FuncLoadError then
  begin
    ASYNC_get_wait_ctx :=  @ERROR_ASYNC_get_wait_ctx;
  end;

  ASYNC_block_pause := LoadLibCryptoFunction('ASYNC_block_pause');
  FuncLoadError := not assigned(ASYNC_block_pause);
  if FuncLoadError then
  begin
    ASYNC_block_pause :=  @ERROR_ASYNC_block_pause;
  end;

  ASYNC_unblock_pause := LoadLibCryptoFunction('ASYNC_unblock_pause');
  FuncLoadError := not assigned(ASYNC_unblock_pause);
  if FuncLoadError then
  begin
    ASYNC_unblock_pause :=  @ERROR_ASYNC_unblock_pause;
  end;

end;

procedure UnLoad;
begin
  ASYNC_init_thread := nil;
  ASYNC_cleanup_thread := nil;
  ASYNC_WAIT_CTX_new := nil;
  ASYNC_WAIT_CTX_free := nil;
  ASYNC_WAIT_CTX_set_wait_fd := nil;
  ASYNC_WAIT_CTX_get_fd := nil;
  ASYNC_WAIT_CTX_get_all_fds := nil;
  ASYNC_WAIT_CTX_get_changed_fds := nil;
  ASYNC_WAIT_CTX_clear_fd := nil;
  ASYNC_is_capable := nil;
  ASYNC_start_job := nil;
  ASYNC_pause_job := nil;
  ASYNC_get_current_job := nil;
  ASYNC_get_wait_ctx := nil;
  ASYNC_block_pause := nil;
  ASYNC_unblock_pause := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
