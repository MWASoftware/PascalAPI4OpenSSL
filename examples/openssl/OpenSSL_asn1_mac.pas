(* This unit was generated from the source file asn1_mac.h2pas 
It should not be modified directly. All changes should be made to asn1_mac.h2pas
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


unit OpenSSL_asn1_mac;


interface

// Headers for OpenSSL 1.1.1
// asn1_mac.h

{.$i IdCompilerDefines.inc}

//#error "This file is obsolete; please update your software."


{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }


{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{$ELSE}
{$ENDIF}

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
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$ENDIF}
finalization


end.
