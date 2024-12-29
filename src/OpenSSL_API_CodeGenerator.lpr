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

program OpenSSL_API_CodeGenerator;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads ,
  {$ENDIF}
  Classes , SysUtils , Tokeniser , APIFileReader , GenerateHeaderUnit ,
  GenerateSmartLoad , GenerateJITUnit , MainUnit , ProgramConstants ;

var
  Application : OpenSSLAPICodeGenerator;
begin
  Application := OpenSSLAPICodeGenerator.Create(nil);
  Application.Title := 'OpenSSL API Code Generator';
  Application.Run;
  Application.Free;
end.

