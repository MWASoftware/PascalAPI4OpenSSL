{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License"), and as
    a derived work of the OpenSSL Project (see below for the original licence text).

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.
}

{$include openssl_defines.inc}

unit openssl_async;

{
  Generated from OpenSSL 3.0.20 Header File async.h - Tue 19 May 14:24:32 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_async.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_asyncerr;


{* Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_ASYNC_H}
  {$define OPENSSL_ASYNC_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_ASYNC_H}
  {$endif}
  {$if  defined(_WIN32)}
    {$if  defined(BASETYPES)  or defined(_WINDEF_H)}

const
      { application has to include <windows.h> to use this }
  OSSL_ASYNC_FD = HANDLE;
  OSSL_BAD_ASYNC_FD = INVALID_HANDLE_VALUE;
    {$endif}
  {$else}

type
  {Auto-generated forward references}
  POSSL_ASYNC_FD = ^TOSSL_ASYNC_FD;
  PPOSSL_ASYNC_FD = ^POSSL_ASYNC_FD;
  {end of auto-generated forward references}

  TOSSL_ASYNC_FD = TOpenSSL_C_INT;

const
  OSSL_BAD_ASYNC_FD = -(1);
  {$endif}

type
  {Auto-generated forward references}
  Pasync_job_st = ^TASYNC_JOB;
  PPasync_job_st = ^Pasync_job_st;
  PASYNC_JOB = ^TASYNC_JOB;
  PPASYNC_JOB = ^PASYNC_JOB;
  Pasync_wait_ctx_st = ^TASYNC_WAIT_CTX;
  PPasync_wait_ctx_st = ^Pasync_wait_ctx_st;
  PASYNC_WAIT_CTX = ^TASYNC_WAIT_CTX;
  PPASYNC_WAIT_CTX = ^PASYNC_WAIT_CTX;
  PASYNC_callback_fn = ^TASYNC_callback_fn;
  PPASYNC_callback_fn = ^PASYNC_callback_fn;
  {end of auto-generated forward references}

  Tasync_job_st = record end;
  TASYNC_JOB = Tasync_job_st;
  Tasync_wait_ctx_st = record end;
  TASYNC_WAIT_CTX = Tasync_wait_ctx_st;
  TASYNC_callback_fn = function(arg: pointer): TOpenSSL_C_INT; cdecl;

const
  ASYNC_ERR = 0;
  ASYNC_NO_JOBS = 1;
  ASYNC_PAUSE = 2;
  ASYNC_FINISH = 3;
  ASYNC_STATUS_UNSUPPORTED = 0;
  ASYNC_STATUS_ERR = 1;
  ASYNC_STATUS_OK = 2;
  ASYNC_STATUS_EAGAIN = 3;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_init_thread';
  procedure ASYNC_cleanup_thread; cdecl; external CLibCrypto name 'ASYNC_cleanup_thread';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM ASYNC_init_thread}
  {$EXTERNALSYM ASYNC_cleanup_thread}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  procedure Load_ASYNC_cleanup_thread; cdecl;

var
  ASYNC_init_thread: function(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_init_thread;
  ASYNC_cleanup_thread: procedure; cdecl = Load_ASYNC_cleanup_thread;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$if declared(TOSSL_ASYNC_FD)}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_new';
  procedure ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_free';
    {$else}
  {$EXTERNALSYM ASYNC_WAIT_CTX_new}
  {$EXTERNALSYM ASYNC_WAIT_CTX_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl;
  procedure Load_ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl;

var
  ASYNC_WAIT_CTX_new: function: PASYNC_WAIT_CTX; cdecl = Load_ASYNC_WAIT_CTX_new;
  ASYNC_WAIT_CTX_free: procedure(ctx: PASYNC_WAIT_CTX); cdecl = Load_ASYNC_WAIT_CTX_free;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = procedure(_param1: PASYNC_WAIT_CTX; _param2: pointer; _param3: TOpenSSL_C_INT; _param4: pointer); cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; key: pointer; fd: TOpenSSL_C_INT; custom_data: pointer; cleanup: TFuncType000): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_set_wait_fd';
  function ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; key: pointer; fd: POpenSSL_C_INT; custom_data: Ppointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_get_fd';
  function ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POpenSSL_C_INT; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_get_all_fds';
  function ASYNC_WAIT_CTX_get_callback(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: Ppointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_get_callback';
  function ASYNC_WAIT_CTX_set_callback(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn; callback_arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_set_callback';
  function ASYNC_WAIT_CTX_set_status(ctx: PASYNC_WAIT_CTX; status: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_set_status';
  function ASYNC_WAIT_CTX_get_status(ctx: PASYNC_WAIT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_get_status';
  function ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POpenSSL_C_INT; numaddfds: POpenSSL_C_SIZET; delfd: POpenSSL_C_INT; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_get_changed_fds';
  function ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; key: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_WAIT_CTX_clear_fd';
    {$else}
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_wait_fd}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_fd}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_all_fds}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_callback}
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_callback}
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_status}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_status}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_changed_fds}
  {$EXTERNALSYM ASYNC_WAIT_CTX_clear_fd}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; key: pointer; fd: TOpenSSL_C_INT; custom_data: pointer; cleanup: TFuncType000): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; key: pointer; fd: POpenSSL_C_INT; custom_data: Ppointer): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POpenSSL_C_INT; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_get_callback(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: Ppointer): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_set_callback(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn; callback_arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_set_status(ctx: PASYNC_WAIT_CTX; status: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_get_status(ctx: PASYNC_WAIT_CTX): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POpenSSL_C_INT; numaddfds: POpenSSL_C_SIZET; delfd: POpenSSL_C_INT; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; key: pointer): TOpenSSL_C_INT; cdecl;

var
  ASYNC_WAIT_CTX_set_wait_fd: function(ctx: PASYNC_WAIT_CTX; key: pointer; fd: TOpenSSL_C_INT; custom_data: pointer; cleanup: TFuncType000): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_set_wait_fd;
  ASYNC_WAIT_CTX_get_fd: function(ctx: PASYNC_WAIT_CTX; key: pointer; fd: POpenSSL_C_INT; custom_data: Ppointer): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_fd;
  ASYNC_WAIT_CTX_get_all_fds: function(ctx: PASYNC_WAIT_CTX; fd: POpenSSL_C_INT; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_all_fds;
  ASYNC_WAIT_CTX_get_callback: function(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: Ppointer): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_callback;
  ASYNC_WAIT_CTX_set_callback: function(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn; callback_arg: pointer): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_set_callback;
  ASYNC_WAIT_CTX_set_status: function(ctx: PASYNC_WAIT_CTX; status: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_set_status;
  ASYNC_WAIT_CTX_get_status: function(ctx: PASYNC_WAIT_CTX): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_status;
  ASYNC_WAIT_CTX_get_changed_fds: function(ctx: PASYNC_WAIT_CTX; addfd: POpenSSL_C_INT; numaddfds: POpenSSL_C_SIZET; delfd: POpenSSL_C_INT; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_changed_fds;
  ASYNC_WAIT_CTX_clear_fd: function(ctx: PASYNC_WAIT_CTX; key: pointer): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_clear_fd;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ASYNC_is_capable: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_is_capable';
  {$else}
  {$EXTERNALSYM ASYNC_is_capable}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ASYNC_is_capable: TOpenSSL_C_INT; cdecl;

var
  ASYNC_is_capable: function: TOpenSSL_C_INT; cdecl = Load_ASYNC_is_capable;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = function(_param1: pointer): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: TFuncType001; args: pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_start_job';
  function ASYNC_pause_job: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ASYNC_pause_job';
  function ASYNC_get_current_job: PASYNC_JOB; cdecl; external CLibCrypto name 'ASYNC_get_current_job';
  function ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl; external CLibCrypto name 'ASYNC_get_wait_ctx';
  procedure ASYNC_block_pause; cdecl; external CLibCrypto name 'ASYNC_block_pause';
  procedure ASYNC_unblock_pause; cdecl; external CLibCrypto name 'ASYNC_unblock_pause';
  {$else}
  {$EXTERNALSYM ASYNC_start_job}
  {$EXTERNALSYM ASYNC_pause_job}
  {$EXTERNALSYM ASYNC_get_current_job}
  {$EXTERNALSYM ASYNC_get_wait_ctx}
  {$EXTERNALSYM ASYNC_block_pause}
  {$EXTERNALSYM ASYNC_unblock_pause}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: TFuncType001; args: pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_pause_job: TOpenSSL_C_INT; cdecl;
  function Load_ASYNC_get_current_job: PASYNC_JOB; cdecl;
  function Load_ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl;
  procedure Load_ASYNC_block_pause; cdecl;
  procedure Load_ASYNC_unblock_pause; cdecl;

var
  ASYNC_start_job: function(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: TFuncType001; args: pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_start_job;
  ASYNC_pause_job: function: TOpenSSL_C_INT; cdecl = Load_ASYNC_pause_job;
  ASYNC_get_current_job: function: PASYNC_JOB; cdecl = Load_ASYNC_get_current_job;
  ASYNC_get_wait_ctx: function(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl = Load_ASYNC_get_wait_ctx;
  ASYNC_block_pause: procedure; cdecl = Load_ASYNC_block_pause;
  ASYNC_unblock_pause: procedure; cdecl = Load_ASYNC_unblock_pause;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}

implementation

uses Sysutils, variants
  {$ifdef OPENSSL_INTERNAL_NEED_THREADS}
   {$IFNDEF FPC}
     ,System.SyncObjs
     {$IFDEF POSIX}
       ,Posix.Pthread
     {$ELSE}
       ,Windows
     {$ENDIF}
   {$ELSE}
     ,SyncObjs
   {$ENDIF}
  {$endif}
  ,Classes, OpenSSLExceptionHandlers;

  {$if not declared(__FILE__)}
  const
    {$ifdef FPC}
    __FILE__ = {$include %FILE%};
    {$else}
    __FILE__ = '$(INPUTFILENAME)';
    {$endif}
  {$ifend}
  {$if not declared(__LINE__)}
  const
    __LINE__ = 0;
  {$ifend}
  {$if not declared(OPENSSL_FILE)}
  const
    OPENSSL_FILE = __FILE__;
  {$ifend}
  {$if not declared(OPENSSL_LINE)}
  const
    OPENSSL_LINE  = 0;
  {$ifend}

{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_init_thread := LoadLibCryptoFunction('ASYNC_init_thread');
  if not assigned(ASYNC_init_thread) then
    {$if declared(LEGACY_ASYNC_init_thread)}
    ASYNC_init_thread := @LEGACY_ASYNC_init_thread;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_init_thread');
    {$ifend}
  Result := ASYNC_init_thread(max_size, init_size);
end;

procedure Load_ASYNC_cleanup_thread; cdecl;
begin
  ASYNC_cleanup_thread := LoadLibCryptoFunction('ASYNC_cleanup_thread');
  if not assigned(ASYNC_cleanup_thread) then
    {$if declared(LEGACY_ASYNC_cleanup_thread)}
    ASYNC_cleanup_thread := @LEGACY_ASYNC_cleanup_thread;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_cleanup_thread');
    {$ifend}
  ASYNC_cleanup_thread;
end;

{$if declared(TOSSL_ASYNC_FD)}
function Load_ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl;
begin
  ASYNC_WAIT_CTX_new := LoadLibCryptoFunction('ASYNC_WAIT_CTX_new');
  if not assigned(ASYNC_WAIT_CTX_new) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_new)}
    ASYNC_WAIT_CTX_new := @LEGACY_ASYNC_WAIT_CTX_new;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_new');
    {$ifend}
  Result := ASYNC_WAIT_CTX_new;
end;

procedure Load_ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl;
begin
  ASYNC_WAIT_CTX_free := LoadLibCryptoFunction('ASYNC_WAIT_CTX_free');
  if not assigned(ASYNC_WAIT_CTX_free) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_free)}
    ASYNC_WAIT_CTX_free := @LEGACY_ASYNC_WAIT_CTX_free;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_free');
    {$ifend}
  ASYNC_WAIT_CTX_free(ctx);
end;

function Load_ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; key: pointer; fd: TOpenSSL_C_INT; custom_data: pointer; cleanup: TFuncType000): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_set_wait_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_set_wait_fd');
  if not assigned(ASYNC_WAIT_CTX_set_wait_fd) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_set_wait_fd)}
    ASYNC_WAIT_CTX_set_wait_fd := @LEGACY_ASYNC_WAIT_CTX_set_wait_fd;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_set_wait_fd');
    {$ifend}
  Result := ASYNC_WAIT_CTX_set_wait_fd(ctx, key, fd, custom_data, cleanup);
end;

function Load_ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; key: pointer; fd: POpenSSL_C_INT; custom_data: Ppointer): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_fd');
  if not assigned(ASYNC_WAIT_CTX_get_fd) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_get_fd)}
    ASYNC_WAIT_CTX_get_fd := @LEGACY_ASYNC_WAIT_CTX_get_fd;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_fd');
    {$ifend}
  Result := ASYNC_WAIT_CTX_get_fd(ctx, key, fd, custom_data);
end;

function Load_ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POpenSSL_C_INT; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_all_fds := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_all_fds');
  if not assigned(ASYNC_WAIT_CTX_get_all_fds) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_get_all_fds)}
    ASYNC_WAIT_CTX_get_all_fds := @LEGACY_ASYNC_WAIT_CTX_get_all_fds;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_all_fds');
    {$ifend}
  Result := ASYNC_WAIT_CTX_get_all_fds(ctx, fd, numfds);
end;

function Load_ASYNC_WAIT_CTX_get_callback(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: Ppointer): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_callback := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_callback');
  if not assigned(ASYNC_WAIT_CTX_get_callback) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_get_callback)}
    ASYNC_WAIT_CTX_get_callback := @LEGACY_ASYNC_WAIT_CTX_get_callback;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_callback');
    {$ifend}
  Result := ASYNC_WAIT_CTX_get_callback(ctx, callback, callback_arg);
end;

function Load_ASYNC_WAIT_CTX_set_callback(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn; callback_arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_set_callback := LoadLibCryptoFunction('ASYNC_WAIT_CTX_set_callback');
  if not assigned(ASYNC_WAIT_CTX_set_callback) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_set_callback)}
    ASYNC_WAIT_CTX_set_callback := @LEGACY_ASYNC_WAIT_CTX_set_callback;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_set_callback');
    {$ifend}
  Result := ASYNC_WAIT_CTX_set_callback(ctx, callback, callback_arg);
end;

function Load_ASYNC_WAIT_CTX_set_status(ctx: PASYNC_WAIT_CTX; status: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_set_status := LoadLibCryptoFunction('ASYNC_WAIT_CTX_set_status');
  if not assigned(ASYNC_WAIT_CTX_set_status) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_set_status)}
    ASYNC_WAIT_CTX_set_status := @LEGACY_ASYNC_WAIT_CTX_set_status;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_set_status');
    {$ifend}
  Result := ASYNC_WAIT_CTX_set_status(ctx, status);
end;

function Load_ASYNC_WAIT_CTX_get_status(ctx: PASYNC_WAIT_CTX): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_status := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_status');
  if not assigned(ASYNC_WAIT_CTX_get_status) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_get_status)}
    ASYNC_WAIT_CTX_get_status := @LEGACY_ASYNC_WAIT_CTX_get_status;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_status');
    {$ifend}
  Result := ASYNC_WAIT_CTX_get_status(ctx);
end;

function Load_ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POpenSSL_C_INT; numaddfds: POpenSSL_C_SIZET; delfd: POpenSSL_C_INT; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_changed_fds := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_changed_fds');
  if not assigned(ASYNC_WAIT_CTX_get_changed_fds) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_get_changed_fds)}
    ASYNC_WAIT_CTX_get_changed_fds := @LEGACY_ASYNC_WAIT_CTX_get_changed_fds;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_changed_fds');
    {$ifend}
  Result := ASYNC_WAIT_CTX_get_changed_fds(ctx, addfd, numaddfds, delfd, numdelfds);
end;

function Load_ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; key: pointer): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_clear_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_clear_fd');
  if not assigned(ASYNC_WAIT_CTX_clear_fd) then
    {$if declared(LEGACY_ASYNC_WAIT_CTX_clear_fd)}
    ASYNC_WAIT_CTX_clear_fd := @LEGACY_ASYNC_WAIT_CTX_clear_fd;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_clear_fd');
    {$ifend}
  Result := ASYNC_WAIT_CTX_clear_fd(ctx, key);
end;

{$endif} {OSSL_ASYNC_FD}
function Load_ASYNC_is_capable: TOpenSSL_C_INT; cdecl;
begin
  ASYNC_is_capable := LoadLibCryptoFunction('ASYNC_is_capable');
  if not assigned(ASYNC_is_capable) then
    {$if declared(LEGACY_ASYNC_is_capable)}
    ASYNC_is_capable := @LEGACY_ASYNC_is_capable;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_is_capable');
    {$ifend}
  Result := ASYNC_is_capable;
end;

function Load_ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: TFuncType001; args: pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_start_job := LoadLibCryptoFunction('ASYNC_start_job');
  if not assigned(ASYNC_start_job) then
    {$if declared(LEGACY_ASYNC_start_job)}
    ASYNC_start_job := @LEGACY_ASYNC_start_job;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_start_job');
    {$ifend}
  Result := ASYNC_start_job(job, ctx, ret, func, args, size);
end;

function Load_ASYNC_pause_job: TOpenSSL_C_INT; cdecl;
begin
  ASYNC_pause_job := LoadLibCryptoFunction('ASYNC_pause_job');
  if not assigned(ASYNC_pause_job) then
    {$if declared(LEGACY_ASYNC_pause_job)}
    ASYNC_pause_job := @LEGACY_ASYNC_pause_job;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_pause_job');
    {$ifend}
  Result := ASYNC_pause_job;
end;

function Load_ASYNC_get_current_job: PASYNC_JOB; cdecl;
begin
  ASYNC_get_current_job := LoadLibCryptoFunction('ASYNC_get_current_job');
  if not assigned(ASYNC_get_current_job) then
    {$if declared(LEGACY_ASYNC_get_current_job)}
    ASYNC_get_current_job := @LEGACY_ASYNC_get_current_job;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_get_current_job');
    {$ifend}
  Result := ASYNC_get_current_job;
end;

function Load_ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl;
begin
  ASYNC_get_wait_ctx := LoadLibCryptoFunction('ASYNC_get_wait_ctx');
  if not assigned(ASYNC_get_wait_ctx) then
    {$if declared(LEGACY_ASYNC_get_wait_ctx)}
    ASYNC_get_wait_ctx := @LEGACY_ASYNC_get_wait_ctx;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_get_wait_ctx');
    {$ifend}
  Result := ASYNC_get_wait_ctx(job);
end;

procedure Load_ASYNC_block_pause; cdecl;
begin
  ASYNC_block_pause := LoadLibCryptoFunction('ASYNC_block_pause');
  if not assigned(ASYNC_block_pause) then
    {$if declared(LEGACY_ASYNC_block_pause)}
    ASYNC_block_pause := @LEGACY_ASYNC_block_pause;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_block_pause');
    {$ifend}
  ASYNC_block_pause;
end;

procedure Load_ASYNC_unblock_pause; cdecl;
begin
  ASYNC_unblock_pause := LoadLibCryptoFunction('ASYNC_unblock_pause');
  if not assigned(ASYNC_unblock_pause) then
    {$if declared(LEGACY_ASYNC_unblock_pause)}
    ASYNC_unblock_pause := @LEGACY_ASYNC_unblock_pause;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_unblock_pause');
    {$ifend}
  ASYNC_unblock_pause;
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  ASYNC_init_thread := Load_ASYNC_init_thread;
  ASYNC_cleanup_thread := Load_ASYNC_cleanup_thread;
{$if declared(TOSSL_ASYNC_FD)}
  ASYNC_WAIT_CTX_new := Load_ASYNC_WAIT_CTX_new;
  ASYNC_WAIT_CTX_free := Load_ASYNC_WAIT_CTX_free;
  ASYNC_WAIT_CTX_set_wait_fd := Load_ASYNC_WAIT_CTX_set_wait_fd;
  ASYNC_WAIT_CTX_get_fd := Load_ASYNC_WAIT_CTX_get_fd;
  ASYNC_WAIT_CTX_get_all_fds := Load_ASYNC_WAIT_CTX_get_all_fds;
  ASYNC_WAIT_CTX_get_callback := Load_ASYNC_WAIT_CTX_get_callback;
  ASYNC_WAIT_CTX_set_callback := Load_ASYNC_WAIT_CTX_set_callback;
  ASYNC_WAIT_CTX_set_status := Load_ASYNC_WAIT_CTX_set_status;
  ASYNC_WAIT_CTX_get_status := Load_ASYNC_WAIT_CTX_get_status;
  ASYNC_WAIT_CTX_get_changed_fds := Load_ASYNC_WAIT_CTX_get_changed_fds;
  ASYNC_WAIT_CTX_clear_fd := Load_ASYNC_WAIT_CTX_clear_fd;
{$endif} {OSSL_ASYNC_FD}
  ASYNC_is_capable := Load_ASYNC_is_capable;
  ASYNC_start_job := Load_ASYNC_start_job;
  ASYNC_pause_job := Load_ASYNC_pause_job;
  ASYNC_get_current_job := Load_ASYNC_get_current_job;
  ASYNC_get_wait_ctx := Load_ASYNC_get_wait_ctx;
  ASYNC_block_pause := Load_ASYNC_block_pause;
  ASYNC_unblock_pause := Load_ASYNC_unblock_pause;
end;

{$endif} {OPENSSL_STATIC_LINK_MODEL}

initialization

{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef EMPTY_LOAD_FUNCTION}
Register_SSLloader(@Load);
{$endif}
Register_SSLUnloader(@Unload);
{$endif}
{$if declared(LegacySupport_Initialization)}
LegacySupport_Initialization;
{$ifend}

finalization

{$if declared(LegacySupport_Finalization)}
LegacySupport_Finalization;
{$ifend}

end.



