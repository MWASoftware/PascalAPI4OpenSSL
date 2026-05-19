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
{$J+}

type
  TOpenSSL_IdCallback = function: TOpenSSL_C_ULONG; cdecl;
  TOpenSSL_LockingCallback = procedure (mode, n : TOpenSSL_C_INT; Afile : PAnsiChar; line : TOpenSSL_C_INT); cdecl;
  Tthreadid_func = procedure (id : PCRYPTO_THREADID) cdecl;  

function Load_Legacy_CRYPTO_mem_ctrl(mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; forward;
function Load_Legacy_CRYPTO_num_locks: TOpenSSL_C_INT; cdecl; forward;
procedure Load_Legacy_CRYPTO_set_locking_callback(func: TOpenSSL_LockingCallback); cdecl; forward;
procedure Load_Legacy_CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl; forward;
procedure Load_Legacy_CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); cdecl; forward;
procedure Load_Legacy_CRYPTO_set_id_callback(func: TOpenSSL_IdCallback); cdecl; forward;
function Load_Legacy_CRYPTO_set_mem_debug(flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; forward;
function Load_Legacy_SSLeay_version(type_ : TOpenSSL_C_INT): PAnsiChar; cdecl; forward;
function Load_Legacy_SSLeay: TOpenSSL_C_ULONG; cdecl; forward;


var
  Legacy_CRYPTO_mem_ctrl: function (mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_Legacy_CRYPTO_mem_ctrl; {removed 3.0.0}
  Legacy_CRYPTO_num_locks: function : TOpenSSL_C_INT; cdecl = Load_Legacy_CRYPTO_num_locks; {removed 1.1.0}
  Legacy_CRYPTO_set_locking_callback: procedure (func: TOpenSSL_LockingCallback); cdecl = Load_Legacy_CRYPTO_set_locking_callback; {removed 1.1.0}
  Legacy_CRYPTO_THREADID_set_numeric: procedure (id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl = Load_Legacy_CRYPTO_THREADID_set_numeric; {removed 1.1.0}
  Legacy_CRYPTO_THREADID_set_callback: procedure (threadid_func: Tthreadid_func); cdecl = Load_Legacy_CRYPTO_THREADID_set_callback; {removed 1.1.0}
  Legacy_CRYPTO_set_id_callback: procedure (func: TOpenSSL_IdCallback); cdecl = Load_Legacy_CRYPTO_set_id_callback; {removed 1.1.0}
  Legacy_CRYPTO_set_mem_debug: function (flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_Legacy_CRYPTO_set_mem_debug; {removed 3.0.0}
  Legacy_SSLeay_version: function (type_ : TOpenSSL_C_INT): PAnsiChar; cdecl = Load_Legacy_SSLeay_version; {removed 1.1.0}
  Legacy_SSLeay: function : TOpenSSL_C_ULONG; cdecl = Load_Legacy_SSLeay; {removed 1.1.0}

function Load_Legacy_CRYPTO_mem_ctrl(mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  Legacy_CRYPTO_mem_ctrl := LoadLibCryptoFunction('CRYPTO_mem_ctrl');
  if not assigned(Legacy_CRYPTO_mem_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_mem_ctrl');
  Result := Legacy_CRYPTO_mem_ctrl(mode);
end;

function Load_Legacy_CRYPTO_num_locks: TOpenSSL_C_INT; cdecl;
begin
  Legacy_CRYPTO_num_locks := LoadLibCryptoFunction('CRYPTO_num_locks');
  if not assigned(Legacy_CRYPTO_num_locks) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_num_locks');
  Result := Legacy_CRYPTO_num_locks();
end;

procedure Load_Legacy_CRYPTO_set_locking_callback(func: TOpenSSL_LockingCallback); cdecl;
begin
  Legacy_CRYPTO_set_locking_callback := LoadLibCryptoFunction('CRYPTO_set_locking_callback');
  if not assigned(Legacy_CRYPTO_set_locking_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_locking_callback');
  Legacy_CRYPTO_set_locking_callback(func);
end;

procedure Load_Legacy_CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl;
begin
  Legacy_CRYPTO_THREADID_set_numeric := LoadLibCryptoFunction('CRYPTO_THREADID_set_numeric');
  if not assigned(Legacy_CRYPTO_THREADID_set_numeric) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREADID_set_numeric');
  Legacy_CRYPTO_THREADID_set_numeric(id,val);
end;

procedure Load_Legacy_CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); cdecl;
begin
  Legacy_CRYPTO_THREADID_set_callback := LoadLibCryptoFunction('CRYPTO_THREADID_set_callback');
  if not assigned(Legacy_CRYPTO_THREADID_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREADID_set_callback');
  Legacy_CRYPTO_THREADID_set_callback(threadid_func);
end;

procedure Load_Legacy_CRYPTO_set_id_callback(func: TOpenSSL_IdCallback); cdecl;
begin
  Legacy_CRYPTO_set_id_callback := LoadLibCryptoFunction('CRYPTO_set_id_callback');
  if not assigned(Legacy_CRYPTO_set_id_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_id_callback');
  Legacy_CRYPTO_set_id_callback(func);
end;

function Load_Legacy_CRYPTO_set_mem_debug(flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  Legacy_CRYPTO_set_mem_debug := LoadLibCryptoFunction('CRYPTO_set_mem_debug');
  if not assigned(Legacy_CRYPTO_set_mem_debug) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_mem_debug');
  Result := Legacy_CRYPTO_set_mem_debug(flag);
end;

function Load_Legacy_SSLeay_version(type_ : TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  Legacy_SSLeay_version := LoadLibCryptoFunction('SSLeay_version');
  if not assigned(Legacy_SSLeay_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSLeay_version');
  Result := Legacy_SSLeay_version(type_);
end;

function Load_Legacy_SSLeay: TOpenSSL_C_ULONG; cdecl;
begin
  Legacy_SSLeay := LoadLibCryptoFunction('SSLeay');
  if not assigned(Legacy_SSLeay) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSLeay');
  Result := Legacy_SSLeay();
end;

function LEGACY_OpenSSL_version(type_ : TOpenSSL_C_INT) : PAnsiChar;
begin
  Result := Legacy_SSLeay_version(type_);
end;

function LEGACY_OpenSSL_version_num: TOpenSSL_C_ULONG;
begin
  Result := Legacy_SSLeay;
end;

function FIPS_mode: TOpenSSL_C_INT;
begin
  Result := OSSL_PROVIDER_available(nil,PAnsiChar(AnsiString('fips')));
end;

var fips_provider: POSSL_PROVIDER;
    base_provider: POSSL_PROVIDER;

function FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT;
begin
  if r = 0 then
  begin
    if base_provider <> nil then
    begin
      OSSL_PROVIDER_unload(base_provider);
      base_provider := nil;
    end;

    if fips_provider <> nil then
    begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
    end;
    Result := 1;
  end
  else
  begin
     Result := 0;
     fips_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('fips')));
     if fips_provider = nil then
       Exit;
     base_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('base')));
     if base_provider = nil then
     begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
       Exit;
     end;
     Result := 1;
  end;
end;


function LEGACY_OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT;
var OpenSSL_add_all_ciphers: procedure; cdecl;
    OpenSSL_add_all_digests: procedure; cdecl;
begin
  Result := 0;
  if opts and OPENSSL_INIT_ADD_ALL_CIPHERS <> 0 then
  begin
    OpenSSL_add_all_ciphers := LoadLibCryptoFunction('OpenSSL_add_all_ciphers');
    if not assigned(OpenSSL_add_all_ciphers) then
      EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_ciphers');
    OpenSSL_add_all_ciphers;
  end;
  if opts and OPENSSL_INIT_ADD_ALL_DIGESTS <> 0 then
  begin
    OpenSSL_add_all_digests := LoadLibCryptoFunction('OpenSSL_add_all_digests');
    if not assigned(OpenSSL_add_all_digests) then
      EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_digests');
    OpenSSL_add_all_digests;
  end;
  Result := 1;
end;

procedure LEGACY_OPENSSL_cleanup;
begin
 {nothing to do}
end;

type

  { TOpenSSLLegacyCallbacks }

  TOpenSSLLegacyCallbacks = class(TThreadList)
  private
    procedure PrepareOpenSSLLocking;
    class var FCallbackList: TOpenSSLLegacyCallbacks;
  public
    constructor Create;
    destructor Destroy; override;
  end;

procedure TOpenSSLLegacyCallbacks.PrepareOpenSSLLocking;
var
  i: integer;
  Lock: TCriticalSection;
begin
  LockList;
  try
    for i := 0 to Legacy_CRYPTO_num_locks - 1 do
    begin
      Lock := TCriticalSection.Create;
      try
        Add(Lock);
      except
        Lock.Free;
        raise;
      end;
    end;
  finally
    UnlockList;
  end;
end;

procedure OpenSSLSetCurrentThreadID(id : PCRYPTO_THREADID); cdecl;
begin
  Legacy_CRYPTO_THREADID_set_numeric(id, TOpenSSL_C_ULONG(GetCurrentThreadId));
end;

procedure OpenSSLLockingCallback(mode, n: TOpenSSL_C_INT; Afile: PAnsiChar;
  line: TOpenSSL_C_INT); cdecl;
var
  Lock: TCriticalSection;
  LList: TList;
begin
  Assert(TOpenSSLLegacyCallbacks.FCallbackList <> nil);
  Lock := nil;

  LList := TOpenSSLLegacyCallbacks.FCallbackList.LockList;
  try
    if n < LList.Count then
      Lock := TCriticalSection(LList[n]);
  finally
    TOpenSSLLegacyCallbacks.FCallbackList.UnlockList;
  end;
  Assert(Lock <> nil);
  if (mode and CRYPTO_LOCK) = CRYPTO_LOCK then
    Lock.Acquire
  else
    Lock.Release;
end;

constructor TOpenSSLLegacyCallbacks.Create;
begin
  Assert(FCallbackList = nil);
  inherited Create;
  FCallbackList := self;
  PrepareOpenSSLLocking;
  Legacy_CRYPTO_set_locking_callback(@OpenSSLLockingCallback);
  Legacy_CRYPTO_THREADID_set_callback(@OpenSSLSetCurrentThreadID);
end;

destructor TOpenSSLLegacyCallbacks.Destroy;
var i: integer;
    LList: TList;
begin
  Legacy_CRYPTO_set_locking_callback(nil);
  LList := LockList;

  try
    for i := 0 to LList.Count - 1 do
      TCriticalSection(LList[i]).Free;
    Clear;
  finally
    UnlockList;
  end;
  inherited Destroy;
  FCallbackList := nil;
end;

{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}


procedure SetLegacyCallbacks;
begin
  {$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  if TOpenSSLLegacyCallbacks.FCallbackList = nil then
    TOpenSSLLegacyCallbacks.Create;
  {$ENDIF}
end;

procedure RemoveLegacyCallbacks;
begin
  {$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  if TOpenSSLLegacyCallbacks.FCallbackList <> nil then
    FreeAndNil(TOpenSSLLegacyCallbacks.FCallbackList);
  {$ENDIF}
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure LegacySupport_Initialization;
begin
  TOpenSSLLegacyCallbacks.FCallbackList := nil;
  fips_provider := nil;
  base_provider := nil;
end; 

procedure LegacySupport_Finalization;
begin
  RemoveLegacyCallbacks;
end;
{$ENDIF}
{$ENDIF}
