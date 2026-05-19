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

unit openssl_byteorder;

{
  Generated from OpenSSL 3.5.6 Header File byteorder.h - Tue 19 May 14:27:08 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_byteorder.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2;


{* Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_BYTEORDER_H}
  {$define OPENSSL_BYTEORDER_H}


  
  {* "Modern" compilers do a decent job of optimising these functions to just a
  * couple of instruction ([swap +] store, or load [+ swap]) when either no
  * swapping is required, or a suitable swap instruction is available.
  }
  
  {#if defined(_MSC_VER) && _MSC_VER >= 1300
  #include <stdlib.h>
  #include <stdlib.h>
  #pragma intrinsic(_byteswap_ushort)
  #pragma intrinsic(_byteswap_ulong)
  #pragma intrinsic(_byteswap_uint64)
  #define OSSL_HTOBE16(x) _byteswap_ushort(x)
  #define OSSL_HTOBE32(x) _byteswap_ulong(x)
  #define OSSL_HTOBE64(x) _byteswap_uint64(x)
  #define OSSL_BE16TOH(x) _byteswap_ushort(x)
  #define OSSL_BE32TOH(x) _byteswap_ulong(x)
  #define OSSL_BE64TOH(x) _byteswap_uint64(x)
  #define OSSL_HTOLE16(x) (x)
  #define OSSL_HTOLE32(x) (x)
  #define OSSL_HTOLE64(x) (x)
  #define OSSL_LE16TOH(x) (x)
  #define OSSL_LE32TOH(x) (x)
  #define OSSL_LE64TOH(x) (x)
  
  #elif defined(__GLIBC__) && defined(__GLIBC_PREREQ)
  #if (__GLIBC_PREREQ(2, 19)) && defined(_DEFAULT_SOURCE)
  #include <endian.h>
  #include <endian.h>
  #define OSSL_HTOBE16(x) htobe16(x)
  #define OSSL_HTOBE32(x) htobe32(x)
  #define OSSL_HTOBE64(x) htobe64(x)
  #define OSSL_BE16TOH(x) be16toh(x)
  #define OSSL_BE32TOH(x) be32toh(x)
  #define OSSL_BE64TOH(x) be64toh(x)
  #define OSSL_HTOLE16(x) htole16(x)
  #define OSSL_HTOLE32(x) htole32(x)
  #define OSSL_HTOLE64(x) htole64(x)
  #define OSSL_LE16TOH(x) le16toh(x)
  #define OSSL_LE32TOH(x) le32toh(x)
  #define OSSL_LE64TOH(x) le64toh(x)
  #endif
  
  #elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #if defined(__OpenBSD__)
  #include <sys/types.h>
  #include <sys/types.h>
  #else
  //#include <sys/endian.h>
  #endif
  #define OSSL_HTOBE16(x) htobe16(x)
  #define OSSL_HTOBE32(x) htobe32(x)
  #define OSSL_HTOBE64(x) htobe64(x)
  #define OSSL_BE16TOH(x) be16toh(x)
  #define OSSL_BE32TOH(x) be32toh(x)
  #define OSSL_BE64TOH(x) be64toh(x)
  #define OSSL_HTOLE16(x) htole16(x)
  #define OSSL_HTOLE32(x) htole32(x)
  #define OSSL_HTOLE64(x) htole64(x)
  #define OSSL_LE16TOH(x) le16toh(x)
  #define OSSL_LE32TOH(x) le32toh(x)
  #define OSSL_LE64TOH(x) le64toh(x)
  
  #elif defined(__APPLE__)
  //#include <libkern/OSByteOrder.h>
  #define OSSL_HTOBE16(x) OSSwapHostToBigInt16(x)
  #define OSSL_HTOBE32(x) OSSwapHostToBigInt32(x)
  #define OSSL_HTOBE64(x) OSSwapHostToBigInt64(x)
  #define OSSL_BE16TOH(x) OSSwapBigToHostInt16(x)
  #define OSSL_BE32TOH(x) OSSwapBigToHostInt32(x)
  #define OSSL_BE64TOH(x) OSSwapBigToHostInt64(x)
  #define OSSL_HTOLE16(x) OSSwapHostToLittleInt16(x)
  #define OSSL_HTOLE32(x) OSSwapHostToLittleInt32(x)
  #define OSSL_HTOLE64(x) OSSwapHostToLittleInt64(x)
  #define OSSL_LE16TOH(x) OSSwapLittleToHostInt16(x)
  #define OSSL_LE32TOH(x) OSSwapLittleToHostInt32(x)
  #define OSSL_LE64TOH(x) OSSwapLittleToHostInt64(x)
  
  #endif
  }
  function OPENSSL_store_u16_le(out_: Pbyte; val: TOpenSSL_C_UINT16): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_store_u16_be(out_: Pbyte; val: TOpenSSL_C_UINT16): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_store_u32_le(out_: Pbyte; val: TOpenSSL_C_UINT): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_store_u32_be(out_: Pbyte; val: TOpenSSL_C_UINT): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_store_u64_le(out_: Pbyte; val: TOpenSSL_C_UINT64): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_store_u64_be(out_: Pbyte; val: TOpenSSL_C_UINT64): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_load_u16_le(val: POpenSSL_C_UINT16; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_load_u16_be(val: POpenSSL_C_UINT16; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_load_u32_le(val: POpenSSL_C_UINT; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_load_u32_be(val: POpenSSL_C_UINT; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_load_u64_le(val: POpenSSL_C_UINT64; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
  function OPENSSL_load_u64_be(val: POpenSSL_C_UINT64; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
  {$undef  OSSL_HTOBE16}
  {$undef  OSSL_HTOBE32}
  {$undef  OSSL_HTOBE64}
  {$undef  OSSL_BE16TOH}
  {$undef  OSSL_BE32TOH}
  {$undef  OSSL_BE64TOH}
  {$undef  OSSL_HTOLE16}
  {$undef  OSSL_HTOLE32}
  {$undef  OSSL_HTOLE64}
  {$undef  OSSL_LE16TOH}
  {$undef  OSSL_LE32TOH}
  {$undef  OSSL_LE64TOH}
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

function OPENSSL_store_u16_le(out_: Pbyte; val: TOpenSSL_C_UINT16): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_store_u16_le"');

{Error: Line 112: Syntax Error parsing "
#ifdef OSSL_HTOLE16
uint16_t t = OSSL_HTOLE16(val);

memcpy(out, (unsigned char *)&t, 2);
return out + 2;
#else
*out++ = (val & 0xff);
*out++ = (val >> 8) & 0xff;
return out;
#endif
"


#ifdef OSSL_HTOLE16
uint16_t t = OSSL_HTOLE16(val);

memcpy(out, (unsigned char *)&t, 2);
return out + 2;
#else
*out++ = (val & 0xff);
*out++ = (val >> 8) & 0xff;
return out;
#endif
}
end;

function OPENSSL_store_u16_be(out_: Pbyte; val: TOpenSSL_C_UINT16): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_store_u16_be"');

{Error: Line 127: Syntax Error parsing "
#ifdef OSSL_HTOBE16
uint16_t t = OSSL_HTOBE16(val);

memcpy(out, (unsigned char *)&t, 2);
return out + 2;
#else
*out++ = (val >> 8) & 0xff;
*out++ = (val & 0xff);
return out;
#endif
"


#ifdef OSSL_HTOBE16
uint16_t t = OSSL_HTOBE16(val);

memcpy(out, (unsigned char *)&t, 2);
return out + 2;
#else
*out++ = (val >> 8) & 0xff;
*out++ = (val & 0xff);
return out;
#endif
}
end;

function OPENSSL_store_u32_le(out_: Pbyte; val: TOpenSSL_C_UINT): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_store_u32_le"');

{Error: Line 144: Syntax Error parsing "
#ifdef OSSL_HTOLE32
uint32_t t = OSSL_HTOLE32(val);

memcpy(out, (unsigned char *)&t, 4);
return out + 4;
#else
*out++ = (val & 0xff);
*out++ = (val >> 8) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 24) & 0xff;
return out;
#endif
"


#ifdef OSSL_HTOLE32
uint32_t t = OSSL_HTOLE32(val);

memcpy(out, (unsigned char *)&t, 4);
return out + 4;
#else
*out++ = (val & 0xff);
*out++ = (val >> 8) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 24) & 0xff;
return out;
#endif
}
end;

function OPENSSL_store_u32_be(out_: Pbyte; val: TOpenSSL_C_UINT): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_store_u32_be"');

{Error: Line 161: Syntax Error parsing "
#ifdef OSSL_HTOBE32
uint32_t t = OSSL_HTOBE32(val);

memcpy(out, (unsigned char *)&t, 4);
return out + 4;
#else
*out++ = (val >> 24) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 8) & 0xff;
*out++ = (val & 0xff);
return out;
#endif
"


#ifdef OSSL_HTOBE32
uint32_t t = OSSL_HTOBE32(val);

memcpy(out, (unsigned char *)&t, 4);
return out + 4;
#else
*out++ = (val >> 24) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 8) & 0xff;
*out++ = (val & 0xff);
return out;
#endif
}
end;

function OPENSSL_store_u64_le(out_: Pbyte; val: TOpenSSL_C_UINT64): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_store_u64_le"');

{Error: Line 182: Syntax Error parsing "
#ifdef OSSL_HTOLE64
uint64_t t = OSSL_HTOLE64(val);

memcpy(out, (unsigned char *)&t, 8);
return out + 8;
#else
*out++ = (val & 0xff);
*out++ = (val >> 8) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 24) & 0xff;
*out++ = (val >> 32) & 0xff;
*out++ = (val >> 40) & 0xff;
*out++ = (val >> 48) & 0xff;
*out++ = (val >> 56) & 0xff;
return out;
#endif
"


#ifdef OSSL_HTOLE64
uint64_t t = OSSL_HTOLE64(val);

memcpy(out, (unsigned char *)&t, 8);
return out + 8;
#else
*out++ = (val & 0xff);
*out++ = (val >> 8) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 24) & 0xff;
*out++ = (val >> 32) & 0xff;
*out++ = (val >> 40) & 0xff;
*out++ = (val >> 48) & 0xff;
*out++ = (val >> 56) & 0xff;
return out;
#endif
}
end;

function OPENSSL_store_u64_be(out_: Pbyte; val: TOpenSSL_C_UINT64): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_store_u64_be"');

{Error: Line 203: Syntax Error parsing "
#ifdef OSSL_HTOLE64
uint64_t t = OSSL_HTOBE64(val);

memcpy(out, (unsigned char *)&t, 8);
return out + 8;
#else
*out++ = (val >> 56) & 0xff;
*out++ = (val >> 48) & 0xff;
*out++ = (val >> 40) & 0xff;
*out++ = (val >> 32) & 0xff;
*out++ = (val >> 24) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 8) & 0xff;
*out++ = (val & 0xff);
return out;
#endif
"


#ifdef OSSL_HTOLE64
uint64_t t = OSSL_HTOBE64(val);

memcpy(out, (unsigned char *)&t, 8);
return out + 8;
#else
*out++ = (val >> 56) & 0xff;
*out++ = (val >> 48) & 0xff;
*out++ = (val >> 40) & 0xff;
*out++ = (val >> 32) & 0xff;
*out++ = (val >> 24) & 0xff;
*out++ = (val >> 16) & 0xff;
*out++ = (val >> 8) & 0xff;
*out++ = (val & 0xff);
return out;
#endif
}
end;

function OPENSSL_load_u16_le(val: POpenSSL_C_UINT16; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_load_u16_le"');

{Error: Line 221: Syntax Error parsing "
#ifdef OSSL_LE16TOH
uint16_t t;

memcpy((unsigned char *)&t, in, 2);
*val = OSSL_LE16TOH(t);
return in + 2;
#else
uint16_t b0 = *in++;
uint16_t b1 = *in++;

*val = b0 | (b1 << 8);
return in;
#endif
"


#ifdef OSSL_LE16TOH
uint16_t t;

memcpy((unsigned char *)&t, in, 2);
*val = OSSL_LE16TOH(t);
return in + 2;
#else
uint16_t b0 = *in++;
uint16_t b1 = *in++;

*val = b0 | (b1 << 8);
return in;
#endif
}
end;

function OPENSSL_load_u16_be(val: POpenSSL_C_UINT16; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_load_u16_be"');

{Error: Line 239: Syntax Error parsing "
#ifdef OSSL_LE16TOH
uint16_t t;

memcpy((unsigned char *)&t, in, 2);
*val = OSSL_BE16TOH(t);
return in + 2;
#else
uint16_t b1 = *in++;
uint16_t b0 = *in++;

*val = b0 | (b1 << 8);
return in;
#endif
"


#ifdef OSSL_LE16TOH
uint16_t t;

memcpy((unsigned char *)&t, in, 2);
*val = OSSL_BE16TOH(t);
return in + 2;
#else
uint16_t b1 = *in++;
uint16_t b0 = *in++;

*val = b0 | (b1 << 8);
return in;
#endif
}
end;

function OPENSSL_load_u32_le(val: POpenSSL_C_UINT; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_load_u32_le"');

{Error: Line 259: Syntax Error parsing "
#ifdef OSSL_LE32TOH
uint32_t t;

memcpy((unsigned char *)&t, in, 4);
*val = OSSL_LE32TOH(t);
return in + 4;
#else
uint32_t b0 = *in++;
uint32_t b1 = *in++;
uint32_t b2 = *in++;
uint32_t b3 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
return in;
#endif
"


#ifdef OSSL_LE32TOH
uint32_t t;

memcpy((unsigned char *)&t, in, 4);
*val = OSSL_LE32TOH(t);
return in + 4;
#else
uint32_t b0 = *in++;
uint32_t b1 = *in++;
uint32_t b2 = *in++;
uint32_t b3 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
return in;
#endif
}
end;

function OPENSSL_load_u32_be(val: POpenSSL_C_UINT; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_load_u32_be"');

{Error: Line 279: Syntax Error parsing "
#ifdef OSSL_LE32TOH
uint32_t t;

memcpy((unsigned char *)&t, in, 4);
*val = OSSL_BE32TOH(t);
return in + 4;
#else
uint32_t b3 = *in++;
uint32_t b2 = *in++;
uint32_t b1 = *in++;
uint32_t b0 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
return in;
#endif
"


#ifdef OSSL_LE32TOH
uint32_t t;

memcpy((unsigned char *)&t, in, 4);
*val = OSSL_BE32TOH(t);
return in + 4;
#else
uint32_t b3 = *in++;
uint32_t b2 = *in++;
uint32_t b1 = *in++;
uint32_t b0 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
return in;
#endif
}
end;

function OPENSSL_load_u64_le(val: POpenSSL_C_UINT64; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_load_u64_le"');

{Error: Line 304: Syntax Error parsing "
#ifdef OSSL_LE64TOH
uint64_t t;

memcpy((unsigned char *)&t, in, 8);
*val = OSSL_LE64TOH(t);
return in + 8;
#else
uint64_t b0 = *in++;
uint64_t b1 = *in++;
uint64_t b2 = *in++;
uint64_t b3 = *in++;
uint64_t b4 = *in++;
uint64_t b5 = *in++;
uint64_t b6 = *in++;
uint64_t b7 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
| (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
return in;
#endif
"


#ifdef OSSL_LE64TOH
uint64_t t;

memcpy((unsigned char *)&t, in, 8);
*val = OSSL_LE64TOH(t);
return in + 8;
#else
uint64_t b0 = *in++;
uint64_t b1 = *in++;
uint64_t b2 = *in++;
uint64_t b3 = *in++;
uint64_t b4 = *in++;
uint64_t b5 = *in++;
uint64_t b6 = *in++;
uint64_t b7 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
| (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
return in;
#endif
}
end;

function OPENSSL_load_u64_be(val: POpenSSL_C_UINT64; in_: Pbyte): Pbyte{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OPENSSL_load_u64_be"');

{Error: Line 329: Syntax Error parsing "
#ifdef OSSL_LE64TOH
uint64_t t;

memcpy((unsigned char *)&t, in, 8);
*val = OSSL_BE64TOH(t);
return in + 8;
#else
uint64_t b7 = *in++;
uint64_t b6 = *in++;
uint64_t b5 = *in++;
uint64_t b4 = *in++;
uint64_t b3 = *in++;
uint64_t b2 = *in++;
uint64_t b1 = *in++;
uint64_t b0 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
| (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
return in;
#endif
"


#ifdef OSSL_LE64TOH
uint64_t t;

memcpy((unsigned char *)&t, in, 8);
*val = OSSL_BE64TOH(t);
return in + 8;
#else
uint64_t b7 = *in++;
uint64_t b6 = *in++;
uint64_t b5 = *in++;
uint64_t b4 = *in++;
uint64_t b3 = *in++;
uint64_t b2 = *in++;
uint64_t b1 = *in++;
uint64_t b0 = *in++;

*val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
| (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
return in;
#endif
}
end;

{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
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



