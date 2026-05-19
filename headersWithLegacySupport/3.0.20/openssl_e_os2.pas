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

unit openssl_e_os2;

{
  Generated from OpenSSL 3.0.20 Header File e_os2.h - Tue 19 May 14:25:04 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_e_os2.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_E_OS2_H}
  {$define OPENSSL_E_OS2_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_E_OS2_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {*****************************************************************************
  * Detect operating systems.  This probably needs completing.
  * The result is that at least one OPENSSL_SYS_os macro should be defined.
  * However, if none is defined, Unix is assumed.
  *}
  {$define OPENSSL_SYS_UNIX}
  { --------------------- Microsoft operating systems ---------------------- }
  
  {* Note that MSDOS actually denotes 32-bit environments running on top of
  * MS-DOS, such as DJGPP one.
  }
  {$if  defined(OPENSSL_SYS_MSDOS)}
    {$undef  OPENSSL_SYS_UNIX}
  {$endif}
  
  {* For 32 bit environment, there seems to be the CygWin environment and then
  * all the others that try to do the same thing Microsoft does...
  }
  
  {* UEFI lives here because it might be built with a Microsoft toolchain and
  * we need to avoid the false positive match on Windows.
  }
  {$if  defined(OPENSSL_SYS_UEFI)}
    {$undef  OPENSSL_SYS_UNIX}
  {$elseif  defined(OPENSSL_SYS_UWIN)}
    {$undef  OPENSSL_SYS_UNIX}
    {$define OPENSSL_SYS_WIN32_UWIN}
  {$else}
    {$if  defined(__CYGWIN__)  or defined(OPENSSL_SYS_CYGWIN)}
      {$define OPENSSL_SYS_WIN32_CYGWIN}
    {$else}
      {$if  defined(_WIN32)  or defined(OPENSSL_SYS_WIN32)}
        {$undef  OPENSSL_SYS_UNIX}
        {$if  not defined(OPENSSL_SYS_WIN32)}
          {$define OPENSSL_SYS_WIN32}
        {$endif}
      {$endif}
      {$if  defined(_WIN64)  or defined(OPENSSL_SYS_WIN64)}
        {$undef  OPENSSL_SYS_UNIX}
        {$if  not defined(OPENSSL_SYS_WIN64)}
          {$define OPENSSL_SYS_WIN64}
        {$endif}
      {$endif}
      {$if  defined(OPENSSL_SYS_WINNT)}
        {$undef  OPENSSL_SYS_UNIX}
      {$endif}
      {$if  defined(OPENSSL_SYS_WINCE)}
        {$undef  OPENSSL_SYS_UNIX}
      {$endif}
    {$endif}
  {$endif}
  { Anything that tries to look like Microsoft is "Windows" }
  {$if  defined(OPENSSL_SYS_WIN32)  or defined(OPENSSL_SYS_WIN64)  or defined(OPENSSL_SYS_WINNT)  or defined(OPENSSL_SYS_WINCE)}
    {$undef  OPENSSL_SYS_UNIX}
    {$define OPENSSL_SYS_WINDOWS}
    {$ifndef  OPENSSL_SYS_MSDOS}
      {$define OPENSSL_SYS_MSDOS}
    {$endif}
  {$endif}
  
  {* DLL settings.  This part is a bit tough, because it's up to the
  * application implementor how he or she will link the application, so it
  * requires some macro to be used.
  }
  {$ifdef OPENSSL_SYS_WINDOWS}
    {$ifndef  OPENSSL_OPT_WINDLL}
      {$if  defined(_WINDLL) }
        { This is used when building OpenSSL to                       * indicate that DLL linkage should be used }
        {$define OPENSSL_OPT_WINDLL}
      {$endif}
    {$endif}
  {$endif}
  { ------------------------------- OpenVMS -------------------------------- }
  {$if  defined(__VMS)  or defined(VMS)}
    {$if  not defined(OPENSSL_SYS_VMS)}
      {$undef  OPENSSL_SYS_UNIX}
      {$define OPENSSL_SYS_VMS}
    {$endif}
    {$if  defined(__DECC)}
      {$define OPENSSL_SYS_VMS_DECC}
    {$elseif  defined(__DECCXX)}
      {$define OPENSSL_SYS_VMS_DECC}
      {$define OPENSSL_SYS_VMS_DECCXX}
    {$else}
      {$define OPENSSL_SYS_VMS_NODECC}
    {$endif}
  {$endif}
  { -------------------------------- Unix ---------------------------------- }
  {$ifdef OPENSSL_SYS_UNIX}
    {$if  defined(linux)  or defined(__linux__)  and  not defined(OPENSSL_SYS_LINUX)}
      {$define OPENSSL_SYS_LINUX}
    {$endif}
    {$if  defined(_AIX)  and  not defined(OPENSSL_SYS_AIX)}
      {$define OPENSSL_SYS_AIX}
    {$endif}
  {$endif}
  { -------------------------------- VOS ----------------------------------- }
  {$if  defined(__VOS__)  and  not defined(OPENSSL_SYS_VOS)}
    {$define OPENSSL_SYS_VOS}
    {$ifdef __HPPA__}
      {$define OPENSSL_SYS_VOS_HPPA}
    {$endif}
    {$ifdef __IA32__}
      {$define OPENSSL_SYS_VOS_IA32}
    {$endif}
  {$endif}
  { ---------------------------- HP NonStop -------------------------------- }
  {$ifdef __TANDEM}
    {$ifdef _STRING}
    {$endif}
    {$define OPENSSL_USE_BUILD_DATE}
    {$if  defined(OPENSSL_THREADS)  and defined(_SPT_MODEL_)}

const
  SPT_THREAD_SIGNAL = 1;
  SPT_THREAD_AWARE = 1;
      {#include <spthread.h>}
    {$elseif  defined(OPENSSL_THREADS)  and defined(_PUT_MODEL_)}
    {$endif}
  {$endif}
  {*
  * That's it for OS-specific stuff
  ****************************************************************************}
  {-
  * OPENSSL_EXTERN is normally used to declare a symbol with possible extra
  * attributes to handle its presence in a shared library.
  * OPENSSL_EXPORT is used to define a symbol with extra possible attributes
  * to make it visible in a shared library.
  * Care needs to be taken when a header file is used both to declare and
  * define symbols.  Basically, for any library that exports some global
  * variables, the following code must be present in the header file that
  * declares them, before OPENSSL_EXTERN is used:
  *
  * #ifdef SOME_BUILD_FLAG_MACRO
  * # undef OPENSSL_EXTERN
  * # define OPENSSL_EXTERN OPENSSL_EXPORT
  * #endif
  *
  * The default is to have OPENSSL_EXPORT and OPENSSL_EXTERN
  * have some generally sensible values.
  }
  {$if  defined(OPENSSL_SYS_WINDOWS)  and defined(OPENSSL_OPT_WINDLL)}
{# define  OPENSSL_EXPORT extern __declspec(dllexport)}
{# define  OPENSSL_EXTERN extern __declspec(dllimport)}
  {$else}
{# define  OPENSSL_EXPORT extern}
{# define  OPENSSL_EXTERN extern}
  {$endif}
  {$ifdef _WIN32}
    {$ifdef _WIN64}

type
  {Auto-generated forward references}
  Possl_ssize_t = ^Tossl_ssize_t;
  PPossl_ssize_t = ^Possl_ssize_t;
  {end of auto-generated forward references}

  Tossl_ssize_t = TOpenSSL_C_LONG;

const
  OSSL_SSIZE_MAX = _I64_MAX;
    {$else}

type
  {Auto-generated forward references}
  Possl_ssize_t = ^Tossl_ssize_t;
  PPossl_ssize_t = ^Possl_ssize_t;
  {end of auto-generated forward references}

  Tossl_ssize_t = TOpenSSL_C_INT;

const
  OSSL_SSIZE_MAX = INT_MAX;
    {$endif}
  {$endif}
  {$if  defined(OPENSSL_SYS_UEFI)  and  not declared(ossl_ssize_t)}

const
  ossl_ssize_t = INTN;
  OSSL_SSIZE_MAX = MAX_INTN;
  {$endif}
  {$if not declared(Tossl_ssize_t)}

type
  {Auto-generated forward references}
  Possl_ssize_t = ^Tossl_ssize_t;
  PPossl_ssize_t = ^Possl_ssize_t;
  {end of auto-generated forward references}

  Tossl_ssize_t = TOpenSSL_C_SSIZET;
    {$if  defined(SSIZE_MAX)}

const
  OSSL_SSIZE_MAX = SSIZE_MAX;
    {$elseif  defined(_POSIX_SSIZE_MAX)}

const
  OSSL_SSIZE_MAX = _POSIX_SSIZE_MAX;
    {$else}
{# define  OSSL_SSIZE_MAX SIZE_MAX>>1)}
    {$endif}
  {$endif}
  {$if  defined(UNUSEDRESULT_DEBUG)}
{# define  __owur __attribute__((__warn_unused_result__))} {Macro Return Type unknown}
  {$else}
    {$define __owur}
  {$endif}
  { Standard integer types }
  {$define OPENSSL_NO_INTTYPES_H}
  {$define OPENSSL_NO_STDINT_H}
  {$if  defined(OPENSSL_SYS_UEFI)}
    {typedef INT8 int8_t; - Redefinition of Builtin Type}
    {typedef UINT8 uint8_t; - Redefinition of Builtin Type}
    {typedef INT16 int16_t; - Redefinition of Builtin Type}
    {typedef UINT16 uint16_t; - Redefinition of Builtin Type}
    {typedef INT32 int32_t; - Redefinition of Builtin Type}
    {typedef UINT32 uint32_t; - Redefinition of Builtin Type}
    {typedef INT64 int64_t; - Redefinition of Builtin Type}
    {typedef UINT64 uint64_t; - Redefinition of Builtin Type}
    { #elif  __STDC_VERSION__ >= 199901L || defined(__osf__) || defined(__sgi) || defined(__hpux) || defined(OPENSSL_SYS_VMS) || defined(__OpenBSD__)
    #include <inttypes.h>
    #include <inttypes.h>
    #undef OPENSSL_NO_INTTYPES_H
     Because the specs say that inttypes.h includes stdint.h if present 
    #undef OPENSSL_NO_STDINT_H
    #elif defined(_MSC_VER) && _MSC_VER < 1600
    
    * minimally required typdefs for systems not supporting inttypes.h or
    * stdint.h: currently just older VC++
    
    typedef signed char int8_t;
    typedef unsigned char uint8_t;
    typedef short int16_t;
    typedef unsigned short uint16_t;
    typedef int int32_t;
    typedef unsigned int uint32_t;
    typedef __int64 int64_t;
    typedef unsigned __int64 uint64_t;
    }
  {$else}
    {$undef  OPENSSL_NO_STDINT_H}
  {$endif}

type
  {Auto-generated forward references}
  Possl_intmax_t = ^Tossl_intmax_t;
  PPossl_intmax_t = ^Possl_intmax_t;
  Possl_uintmax_t = ^Tossl_uintmax_t;
  PPossl_uintmax_t = ^Possl_uintmax_t;
  {end of auto-generated forward references}

  { Commented out to avoid Delphi errors
  #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && defined(INTMAX_MAX) && defined(UINTMAX_MAX)
  typedef intmax_t ossl_intmax_t;
  typedef uintmax_t ossl_uintmax_t;
  #else }
  { Fall back to the largest we know we require and can handle }
  Tossl_intmax_t = TOpenSSL_C_LONG;
  Tossl_uintmax_t = TOpenSSL_C_UINT64;
  {# define  ossl_inline inline} { Blacklisted Macro}
  {# define  ossl_noreturn __attribute__((noreturn))} {Macro Return Type unknown}
  {# define  ossl_unused __attribute__((unused))} {Macro Return Type unknown}
  {#endif}
  { ossl_inline: portable inline definition usable in public headers }
  { Causes runtime problems for Pascal - inline is reserved word
  #if !defined(inline) && !defined(__cplusplus)
  #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
   just use inline 
  #define ossl_inline inline
  #elif defined(__GNUC__) && __GNUC__ >= 2
  #define ossl_inline __inline__
  #elif defined(_MSC_VER)
  / *
  * Visual Studio: inline is available in C++ only, however
  * __inline is available for C, see
  * http://msdn.microsoft.com/en-us/library/z8y1yy88.aspx
  * /
  #define ossl_inline __inline
  #else
  #define ossl_inline
  #endif
  #else
  }
  {#endif}
  { #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
  //#define ossl_noreturn _Noreturn
  #define ossl_noreturn
  #elif defined(__GNUC__) && __GNUC__ >= 2
  }
  { #else
  #define ossl_noreturn
  #endif
  }
  { ossl_unused: portable unused attribute for use in public headers }
  { #if defined(__GNUC__)}
  { #else
  #define ossl_unused
  #endif
  }
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



