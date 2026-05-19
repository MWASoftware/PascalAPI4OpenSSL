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
    
{$ifndef OPENSSL_STATIC_LINK_MODEL}
var
  Legacy_ERR_put_error: procedure (lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; 
           file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = nil; {removed 3.0.0}
{$endif}
    
    
procedure ERR_put_error(lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; file_: PAnsiChar; line: TOpenSSL_C_INT);
{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), ''))}
begin
{$ifndef OPENSSL_STATIC_LINK_MODEL}
  if assigned(Legacy_ERR_put_error) then
    Legacy_ERR_put_error(lib,func,reason,file_,line)
  else
  begin
{$endif}
  ERR_new;
  ERR_set_debug(file_,line, '');
  ERR_set_error(lib,reason,'');
{$ifndef OPENSSL_STATIC_LINK_MODEL}
  end;
 {$endif}
end;

procedure X509err(const f,r : TOpenSSL_C_INT);
begin
  ERR_PUT_error(ERR_LIB_X509,f,r,nil,0);
end;

procedure SSLErr(func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT);
begin
  ERR_put_error(ERR_LIB_SSL,func,reason,'',0);
end; 

{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Legacy_Load;
begin
  Legacy_ERR_put_error := LoadLibCryptoFunction('ERR_put_error');
end;

procedure Legacy_UnLoad;
begin
  Legacy_ERR_put_error := nil;
end;

procedure LegacySupport_Initialization;
begin
  Register_SSLLoader(@Legacy_Load);
  Register_SSLUnLoader(@Legacy_Unload);
end;
{$endif}
