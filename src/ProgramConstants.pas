{
    This file is part of the MWA Software Pascal API Code Generator for OpenSSL .

    Copyright © MWA Software 2024

    This program is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <https://www.gnu.org/licenses/>.

    }

unit ProgramConstants;

{$IFDEF FPC}
{$mode Delphi}
{$ENDIF}

(* This unit defines global constants used by the Code Generator and which
   could be made into program arguments in future versions *)

interface


const
    CryptoLibName         = 'LibCrypto';
    NoLegacySupportSymbol = 'OPENSSL_NO_LEGACY_SUPPORT';
    StaticLinkModel       = 'OPENSSL_STATIC_LINK_MODEL';
    ErrorExceptionClassName = 'EOpenSSLAPIFunctionNotPresent';


    {Target OpenSSL Library Version}
    BaseMajorVersion = 3;
    BaseMinorVersion = 0;
    BasePatchVersion = 0;

    ImplementationSectionUses: array [0..2] of string = ('Classes','OpenSSLExceptionHandlers','OpenSSLResourceStrings');



implementation

end.

