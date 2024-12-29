{
This file is part of the MWA Software Pascal API Code Generator for OpenSSL.

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

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  APIFileReader in 'APIFileReader.pas',
  GenerateHeaderUnit in 'GenerateHeaderUnit.pas',
  GenerateJITUnit in 'GenerateJITUnit.pas',
  GenerateSmartLoad in 'GenerateSmartLoad.pas',
  MainUnit in 'MainUnit.pas',
  Tokeniser in 'Tokeniser.pas',
  ProgramConstants in 'ProgramConstants.pas';

var
  Application : OpenSSLAPICodeGenerator;
begin
  try
  Application := OpenSSLAPICodeGenerator.Create(nil);
  Application.Title := 'OpenSSL API Code Generator';
  Application.Run;
  Application.Free;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
