(* This unit was generated from the source file des.h2pas 
It should not be modified directly. All changes should be made to des.h2pas
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



unit OpenSSL_des;


interface


uses
  OpenSSLAPI;

{
  Automatically converted by H2Pas 1.0.0 from des.h
  The following command line parameters were used:
    des.h
}

    
Type
    DES_LONG = type cardinal;
    Pconst_DES_cblock  = ^const_DES_cblock;
    PDES_cblock  = ^DES_cblock;
    PDES_key_schedule  = ^DES_key_schedule;
    PDES_LONG  = ^DES_LONG;


     DES_cblock = array[0..7] of byte;
    { const  }
      const_DES_cblock = array[0..7] of byte;
    {
     * With "const", gcc 2.8.1 on Solaris thinks that DES_cblock * and
     * const_DES_cblock * are incompatible pointer types.
      }
    {
             * make sure things are correct size on machines with 8 byte longs
              }

      DES_ks = record
          ks : array[0..15] of record
              case longint of
                0 : ( cblock : DES_cblock );
                1 : ( deslong : array[0..1] of DES_LONG );
              end;
        end;
      DES_key_schedule = DES_ks;

var
  DES_check_key : longint;


    
const
      DES_ENCRYPT = 1;      
      DES_DECRYPT = 0;      
      DES_CBC_MODE = 0;      
      DES_PCBC_MODE = 1;      

    
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM DES_options}
{$EXTERNALSYM DES_ecb3_encrypt}
{$EXTERNALSYM DES_cbc_cksum}
{$EXTERNALSYM DES_cbc_encrypt}
{$EXTERNALSYM DES_ncbc_encrypt}
{$EXTERNALSYM DES_xcbc_encrypt}
{$EXTERNALSYM DES_cfb_encrypt}
{$EXTERNALSYM DES_ecb_encrypt}
{$EXTERNALSYM DES_encrypt1}
{$EXTERNALSYM DES_encrypt2}
{$EXTERNALSYM DES_encrypt3}
{$EXTERNALSYM DES_decrypt3}
{$EXTERNALSYM DES_ede3_cbc_encrypt}
{$EXTERNALSYM DES_ede3_cfb64_encrypt}
{$EXTERNALSYM DES_ede3_cfb_encrypt}
{$EXTERNALSYM DES_ede3_ofb64_encrypt}
{$EXTERNALSYM DES_fcrypt}
{$EXTERNALSYM DES_crypt}
{$EXTERNALSYM DES_ofb_encrypt}
{$EXTERNALSYM DES_pcbc_encrypt}
{$EXTERNALSYM DES_quad_cksum}
{$EXTERNALSYM DES_random_key}
{$EXTERNALSYM DES_set_odd_parity}
{$EXTERNALSYM DES_check_key_parity}
{$EXTERNALSYM DES_is_weak_key}
{$EXTERNALSYM DES_set_key}
{$EXTERNALSYM DES_key_sched}
{$EXTERNALSYM DES_set_key_checked}
{$EXTERNALSYM DES_set_key_unchecked}
{$EXTERNALSYM DES_string_to_key}
{$EXTERNALSYM DES_string_to_2keys}
{$EXTERNALSYM DES_cfb64_encrypt}
{$EXTERNALSYM DES_ofb64_encrypt}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function DES_options: PAnsiChar; cdecl; external CLibCrypto;
procedure DES_ecb3_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
function DES_cbc_cksum(input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock): DES_LONG; cdecl; external CLibCrypto;
procedure DES_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ncbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_xcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ecb_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
procedure DES_encrypt1(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
procedure DES_encrypt2(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
procedure DES_encrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl; external CLibCrypto;
procedure DES_decrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl; external CLibCrypto;
procedure DES_ede3_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ede3_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl; external CLibCrypto;
procedure DES_ede3_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ede3_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl; external CLibCrypto;
function DES_fcrypt(buf:PAnsiChar; salt:PAnsiChar; ret:PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function DES_crypt(buf:PAnsiChar; salt:PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
procedure DES_ofb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl; external CLibCrypto;
procedure DES_pcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
function DES_quad_cksum(input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock): DES_LONG; cdecl; external CLibCrypto;
function DES_random_key(ret:PDES_cblock): longint; cdecl; external CLibCrypto;
procedure DES_set_odd_parity(key:PDES_cblock); cdecl; external CLibCrypto;
function DES_check_key_parity(key:Pconst_DES_cblock): longint; cdecl; external CLibCrypto;
function DES_is_weak_key(key:Pconst_DES_cblock): longint; cdecl; external CLibCrypto;
function DES_set_key(key:Pconst_DES_cblock; var schedule: DES_key_schedule): longint; cdecl; external CLibCrypto;
function DES_key_sched(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl; external CLibCrypto;
function DES_set_key_checked(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl; external CLibCrypto;
procedure DES_set_key_unchecked(key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl; external CLibCrypto;
procedure DES_string_to_key(str:PAnsiChar; key:PDES_cblock); cdecl; external CLibCrypto;
procedure DES_string_to_2keys(str:PAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl; external CLibCrypto;
procedure DES_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl; external CLibCrypto;
procedure DES_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); {removed 1.0.0}
procedure DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); {removed 1.0.0}
procedure DES_ede2_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); {removed 1.0.0}
procedure DES_ede2_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); {removed 1.0.0}
procedure DES_fixup_key_parity(key: PDES_cblock); {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  DES_options: function : PAnsiChar; cdecl = nil;
  DES_ecb3_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl = nil;
  DES_cbc_cksum: function (input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock): DES_LONG; cdecl = nil;
  DES_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;
  DES_ncbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;
  DES_xcbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl = nil;
  DES_cfb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;
  DES_ecb_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl = nil;
  DES_encrypt1: procedure (data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl = nil;
  DES_encrypt2: procedure (data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl = nil;
  DES_encrypt3: procedure (data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl = nil;
  DES_decrypt3: procedure (data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl = nil;
  DES_ede3_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;
  DES_ede3_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = nil;
  DES_ede3_cfb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;
  DES_ede3_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = nil;
  DES_fcrypt: function (buf:PAnsiChar; salt:PAnsiChar; ret:PAnsiChar): PAnsiChar; cdecl = nil;
  DES_crypt: function (buf:PAnsiChar; salt:PAnsiChar): PAnsiChar; cdecl = nil;
  DES_ofb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl = nil;
  DES_pcbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;
  DES_quad_cksum: function (input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock): DES_LONG; cdecl = nil;
  DES_random_key: function (ret:PDES_cblock): longint; cdecl = nil;
  DES_set_odd_parity: procedure (key:PDES_cblock); cdecl = nil;
  DES_check_key_parity: function (key:Pconst_DES_cblock): longint; cdecl = nil;
  DES_is_weak_key: function (key:Pconst_DES_cblock): longint; cdecl = nil;
  DES_set_key: function (key:Pconst_DES_cblock; var schedule: DES_key_schedule): longint; cdecl = nil;
  DES_key_sched: function (key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl = nil;
  DES_set_key_checked: function (key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl = nil;
  DES_set_key_unchecked: procedure (key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl = nil;
  DES_string_to_key: procedure (str:PAnsiChar; key:PDES_cblock); cdecl = nil;
  DES_string_to_2keys: procedure (str:PAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl = nil;
  DES_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = nil;
  DES_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = nil;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  DES_ecb2_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); cdecl = nil; {removed 1.0.0}
  DES_ede2_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil; {removed 1.0.0}
  DES_ede2_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = nil; {removed 1.0.0}
  DES_ede2_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = nil; {removed 1.0.0}
  DES_fixup_key_parity: procedure (key: PDES_cblock); cdecl = nil; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  DES_ecb2_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_ede2_cbc_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_ede2_cfb64_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_ede2_ofb64_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_fixup_key_parity_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}


implementation

    
uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: longint);

    begin
      DES_ecb3_encrypt(input,output,ks1,ks2,ks1,enc);
    end;

    

procedure DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; enc: longint);

    begin
      DES_ede3_cbc_encrypt(input,output,length,ks1,ks2,ks1,ivec,enc);
    end;

    

procedure DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint; enc: longint);

    begin
      DES_ede3_cfb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num,enc);
    end;

    

procedure DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint);

    begin
      DES_ede3_ofb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num);
    end;

    

procedure DES_fixup_key_parity(key:PDES_cblock);

    begin
      DES_set_odd_parity(key);
   end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure COMPAT_DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: longint); cdecl;

    begin
      DES_ecb3_encrypt(input,output,ks1,ks2,ks1,enc);
    end;

    

procedure COMPAT_DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; enc: longint); cdecl;

    begin
      DES_ede3_cbc_encrypt(input,output,length,ks1,ks2,ks1,ivec,enc);
    end;

    

procedure COMPAT_DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint; enc: longint); cdecl;

    begin
      DES_ede3_cfb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num,enc);
    end;

    

procedure COMPAT_DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint); cdecl;

    begin
      DES_ede3_ofb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num);
    end;

    

procedure COMPAT_DES_fixup_key_parity(key:PDES_cblock); cdecl;

    begin
      DES_set_odd_parity(key);
   end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ecb2_encrypt');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede2_cbc_encrypt');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_DES_ede2_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede2_cfb64_encrypt');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_DES_ede2_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede2_ofb64_encrypt');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_DES_options: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_options');
end;

procedure ERROR_DES_ecb3_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ecb3_encrypt');
end;

function ERROR_DES_cbc_cksum(input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock): DES_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cbc_cksum');
end;

procedure ERROR_DES_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cbc_encrypt');
end;

procedure ERROR_DES_ncbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ncbc_encrypt');
end;

procedure ERROR_DES_xcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_xcbc_encrypt');
end;

procedure ERROR_DES_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cfb_encrypt');
end;

procedure ERROR_DES_ecb_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ecb_encrypt');
end;

procedure ERROR_DES_encrypt1(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt1');
end;

procedure ERROR_DES_encrypt2(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt2');
end;

procedure ERROR_DES_encrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt3');
end;

procedure ERROR_DES_decrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_decrypt3');
end;

procedure ERROR_DES_ede3_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cbc_encrypt');
end;

procedure ERROR_DES_ede3_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cfb64_encrypt');
end;

procedure ERROR_DES_ede3_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cfb_encrypt');
end;

procedure ERROR_DES_ede3_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_ofb64_encrypt');
end;

function ERROR_DES_fcrypt(buf:PAnsiChar; salt:PAnsiChar; ret:PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_fcrypt');
end;

function ERROR_DES_crypt(buf:PAnsiChar; salt:PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_crypt');
end;

procedure ERROR_DES_ofb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ofb_encrypt');
end;

procedure ERROR_DES_pcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_pcbc_encrypt');
end;

function ERROR_DES_quad_cksum(input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock): DES_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_quad_cksum');
end;

function ERROR_DES_random_key(ret:PDES_cblock): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_random_key');
end;

function ERROR_DES_check_key_parity(key:Pconst_DES_cblock): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_check_key_parity');
end;

function ERROR_DES_is_weak_key(key:Pconst_DES_cblock): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_is_weak_key');
end;

function ERROR_DES_key_sched(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_key_sched');
end;

function ERROR_DES_set_key_checked(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_key_checked');
end;

procedure ERROR_DES_set_key_unchecked(key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_key_unchecked');
end;

procedure ERROR_DES_string_to_key(str:PAnsiChar; key:PDES_cblock); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_string_to_key');
end;

procedure ERROR_DES_string_to_2keys(str:PAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_string_to_2keys');
end;

procedure ERROR_DES_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cfb64_encrypt');
end;

procedure ERROR_DES_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ofb64_encrypt');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_DES_fixup_key_parity(key: PDES_cblock); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DES_fixup_key_parity');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  DES_ecb2_encrypt := LoadLibCryptoFunction('DES_ecb2_encrypt');
  FuncLoadError := not assigned(DES_ecb2_encrypt);
  if FuncLoadError then
  begin
    DES_ecb2_encrypt := @COMPAT_DES_ecb2_encrypt;
    if DES_ecb2_encrypt_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('DES_ecb2_encrypt');
  end;

  DES_ede2_cbc_encrypt := LoadLibCryptoFunction('DES_ede2_cbc_encrypt');
  FuncLoadError := not assigned(DES_ede2_cbc_encrypt);
  if FuncLoadError then
  begin
    DES_ede2_cbc_encrypt := @COMPAT_DES_ede2_cbc_encrypt;
    if DES_ede2_cbc_encrypt_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('DES_ede2_cbc_encrypt');
  end;

  DES_ede2_cfb64_encrypt := LoadLibCryptoFunction('DES_ede2_cfb64_encrypt');
  FuncLoadError := not assigned(DES_ede2_cfb64_encrypt);
  if FuncLoadError then
  begin
    DES_ede2_cfb64_encrypt := @COMPAT_DES_ede2_cfb64_encrypt;
    if DES_ede2_cfb64_encrypt_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('DES_ede2_cfb64_encrypt');
  end;

  DES_ede2_ofb64_encrypt := LoadLibCryptoFunction('DES_ede2_ofb64_encrypt');
  FuncLoadError := not assigned(DES_ede2_ofb64_encrypt);
  if FuncLoadError then
  begin
    DES_ede2_ofb64_encrypt := @COMPAT_DES_ede2_ofb64_encrypt;
    if DES_ede2_ofb64_encrypt_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('DES_ede2_ofb64_encrypt');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  DES_options := LoadLibCryptoFunction('DES_options');
  FuncLoadError := not assigned(DES_options);
  if FuncLoadError then
  begin
    DES_options :=  @ERROR_DES_options;
  end;

  DES_ecb3_encrypt := LoadLibCryptoFunction('DES_ecb3_encrypt');
  FuncLoadError := not assigned(DES_ecb3_encrypt);
  if FuncLoadError then
  begin
    DES_ecb3_encrypt :=  @ERROR_DES_ecb3_encrypt;
  end;

  DES_cbc_cksum := LoadLibCryptoFunction('DES_cbc_cksum');
  FuncLoadError := not assigned(DES_cbc_cksum);
  if FuncLoadError then
  begin
    DES_cbc_cksum :=  @ERROR_DES_cbc_cksum;
  end;

  DES_cbc_encrypt := LoadLibCryptoFunction('DES_cbc_encrypt');
  FuncLoadError := not assigned(DES_cbc_encrypt);
  if FuncLoadError then
  begin
    DES_cbc_encrypt :=  @ERROR_DES_cbc_encrypt;
  end;

  DES_ncbc_encrypt := LoadLibCryptoFunction('DES_ncbc_encrypt');
  FuncLoadError := not assigned(DES_ncbc_encrypt);
  if FuncLoadError then
  begin
    DES_ncbc_encrypt :=  @ERROR_DES_ncbc_encrypt;
  end;

  DES_xcbc_encrypt := LoadLibCryptoFunction('DES_xcbc_encrypt');
  FuncLoadError := not assigned(DES_xcbc_encrypt);
  if FuncLoadError then
  begin
    DES_xcbc_encrypt :=  @ERROR_DES_xcbc_encrypt;
  end;

  DES_cfb_encrypt := LoadLibCryptoFunction('DES_cfb_encrypt');
  FuncLoadError := not assigned(DES_cfb_encrypt);
  if FuncLoadError then
  begin
    DES_cfb_encrypt :=  @ERROR_DES_cfb_encrypt;
  end;

  DES_ecb_encrypt := LoadLibCryptoFunction('DES_ecb_encrypt');
  FuncLoadError := not assigned(DES_ecb_encrypt);
  if FuncLoadError then
  begin
    DES_ecb_encrypt :=  @ERROR_DES_ecb_encrypt;
  end;

  DES_encrypt1 := LoadLibCryptoFunction('DES_encrypt1');
  FuncLoadError := not assigned(DES_encrypt1);
  if FuncLoadError then
  begin
    DES_encrypt1 :=  @ERROR_DES_encrypt1;
  end;

  DES_encrypt2 := LoadLibCryptoFunction('DES_encrypt2');
  FuncLoadError := not assigned(DES_encrypt2);
  if FuncLoadError then
  begin
    DES_encrypt2 :=  @ERROR_DES_encrypt2;
  end;

  DES_encrypt3 := LoadLibCryptoFunction('DES_encrypt3');
  FuncLoadError := not assigned(DES_encrypt3);
  if FuncLoadError then
  begin
    DES_encrypt3 :=  @ERROR_DES_encrypt3;
  end;

  DES_decrypt3 := LoadLibCryptoFunction('DES_decrypt3');
  FuncLoadError := not assigned(DES_decrypt3);
  if FuncLoadError then
  begin
    DES_decrypt3 :=  @ERROR_DES_decrypt3;
  end;

  DES_ede3_cbc_encrypt := LoadLibCryptoFunction('DES_ede3_cbc_encrypt');
  FuncLoadError := not assigned(DES_ede3_cbc_encrypt);
  if FuncLoadError then
  begin
    DES_ede3_cbc_encrypt :=  @ERROR_DES_ede3_cbc_encrypt;
  end;

  DES_ede3_cfb64_encrypt := LoadLibCryptoFunction('DES_ede3_cfb64_encrypt');
  FuncLoadError := not assigned(DES_ede3_cfb64_encrypt);
  if FuncLoadError then
  begin
    DES_ede3_cfb64_encrypt :=  @ERROR_DES_ede3_cfb64_encrypt;
  end;

  DES_ede3_cfb_encrypt := LoadLibCryptoFunction('DES_ede3_cfb_encrypt');
  FuncLoadError := not assigned(DES_ede3_cfb_encrypt);
  if FuncLoadError then
  begin
    DES_ede3_cfb_encrypt :=  @ERROR_DES_ede3_cfb_encrypt;
  end;

  DES_ede3_ofb64_encrypt := LoadLibCryptoFunction('DES_ede3_ofb64_encrypt');
  FuncLoadError := not assigned(DES_ede3_ofb64_encrypt);
  if FuncLoadError then
  begin
    DES_ede3_ofb64_encrypt :=  @ERROR_DES_ede3_ofb64_encrypt;
  end;

  DES_fcrypt := LoadLibCryptoFunction('DES_fcrypt');
  FuncLoadError := not assigned(DES_fcrypt);
  if FuncLoadError then
  begin
    DES_fcrypt :=  @ERROR_DES_fcrypt;
  end;

  DES_crypt := LoadLibCryptoFunction('DES_crypt');
  FuncLoadError := not assigned(DES_crypt);
  if FuncLoadError then
  begin
    DES_crypt :=  @ERROR_DES_crypt;
  end;

  DES_ofb_encrypt := LoadLibCryptoFunction('DES_ofb_encrypt');
  FuncLoadError := not assigned(DES_ofb_encrypt);
  if FuncLoadError then
  begin
    DES_ofb_encrypt :=  @ERROR_DES_ofb_encrypt;
  end;

  DES_pcbc_encrypt := LoadLibCryptoFunction('DES_pcbc_encrypt');
  FuncLoadError := not assigned(DES_pcbc_encrypt);
  if FuncLoadError then
  begin
    DES_pcbc_encrypt :=  @ERROR_DES_pcbc_encrypt;
  end;

  DES_quad_cksum := LoadLibCryptoFunction('DES_quad_cksum');
  FuncLoadError := not assigned(DES_quad_cksum);
  if FuncLoadError then
  begin
    DES_quad_cksum :=  @ERROR_DES_quad_cksum;
  end;

  DES_random_key := LoadLibCryptoFunction('DES_random_key');
  FuncLoadError := not assigned(DES_random_key);
  if FuncLoadError then
  begin
    DES_random_key :=  @ERROR_DES_random_key;
  end;

  DES_set_odd_parity := LoadLibCryptoFunction('DES_set_odd_parity');
  FuncLoadError := not assigned(DES_set_odd_parity);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  DES_check_key_parity := LoadLibCryptoFunction('DES_check_key_parity');
  FuncLoadError := not assigned(DES_check_key_parity);
  if FuncLoadError then
  begin
    DES_check_key_parity :=  @ERROR_DES_check_key_parity;
  end;

  DES_is_weak_key := LoadLibCryptoFunction('DES_is_weak_key');
  FuncLoadError := not assigned(DES_is_weak_key);
  if FuncLoadError then
  begin
    DES_is_weak_key :=  @ERROR_DES_is_weak_key;
  end;

  DES_set_key := LoadLibCryptoFunction('DES_set_key');
  FuncLoadError := not assigned(DES_set_key);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  DES_key_sched := LoadLibCryptoFunction('DES_key_sched');
  FuncLoadError := not assigned(DES_key_sched);
  if FuncLoadError then
  begin
    DES_key_sched :=  @ERROR_DES_key_sched;
  end;

  DES_set_key_checked := LoadLibCryptoFunction('DES_set_key_checked');
  FuncLoadError := not assigned(DES_set_key_checked);
  if FuncLoadError then
  begin
    DES_set_key_checked :=  @ERROR_DES_set_key_checked;
  end;

  DES_set_key_unchecked := LoadLibCryptoFunction('DES_set_key_unchecked');
  FuncLoadError := not assigned(DES_set_key_unchecked);
  if FuncLoadError then
  begin
    DES_set_key_unchecked :=  @ERROR_DES_set_key_unchecked;
  end;

  DES_string_to_key := LoadLibCryptoFunction('DES_string_to_key');
  FuncLoadError := not assigned(DES_string_to_key);
  if FuncLoadError then
  begin
    DES_string_to_key :=  @ERROR_DES_string_to_key;
  end;

  DES_string_to_2keys := LoadLibCryptoFunction('DES_string_to_2keys');
  FuncLoadError := not assigned(DES_string_to_2keys);
  if FuncLoadError then
  begin
    DES_string_to_2keys :=  @ERROR_DES_string_to_2keys;
  end;

  DES_cfb64_encrypt := LoadLibCryptoFunction('DES_cfb64_encrypt');
  FuncLoadError := not assigned(DES_cfb64_encrypt);
  if FuncLoadError then
  begin
    DES_cfb64_encrypt :=  @ERROR_DES_cfb64_encrypt;
  end;

  DES_ofb64_encrypt := LoadLibCryptoFunction('DES_ofb64_encrypt');
  FuncLoadError := not assigned(DES_ofb64_encrypt);
  if FuncLoadError then
  begin
    DES_ofb64_encrypt :=  @ERROR_DES_ofb64_encrypt;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  DES_fixup_key_parity := LoadLibCryptoFunction('DES_fixup_key_parity');
  FuncLoadError := not assigned(DES_fixup_key_parity);
  if FuncLoadError then
  begin
    DES_fixup_key_parity := @COMPAT_DES_fixup_key_parity;
    if DES_fixup_key_parity_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('DES_fixup_key_parity');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  DES_ecb2_encrypt := nil;
  DES_ede2_cbc_encrypt := nil;
  DES_ede2_cfb64_encrypt := nil;
  DES_ede2_ofb64_encrypt := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  DES_options := nil;
  DES_ecb3_encrypt := nil;
  DES_cbc_cksum := nil;
  DES_cbc_encrypt := nil;
  DES_ncbc_encrypt := nil;
  DES_xcbc_encrypt := nil;
  DES_cfb_encrypt := nil;
  DES_ecb_encrypt := nil;
  DES_encrypt1 := nil;
  DES_encrypt2 := nil;
  DES_encrypt3 := nil;
  DES_decrypt3 := nil;
  DES_ede3_cbc_encrypt := nil;
  DES_ede3_cfb64_encrypt := nil;
  DES_ede3_cfb_encrypt := nil;
  DES_ede3_ofb64_encrypt := nil;
  DES_fcrypt := nil;
  DES_crypt := nil;
  DES_ofb_encrypt := nil;
  DES_pcbc_encrypt := nil;
  DES_quad_cksum := nil;
  DES_random_key := nil;
  DES_set_odd_parity := nil;
  DES_check_key_parity := nil;
  DES_is_weak_key := nil;
  DES_set_key := nil;
  DES_key_sched := nil;
  DES_set_key_checked := nil;
  DES_set_key_unchecked := nil;
  DES_string_to_key := nil;
  DES_string_to_2keys := nil;
  DES_cfb64_encrypt := nil;
  DES_ofb64_encrypt := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  DES_fixup_key_parity := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
