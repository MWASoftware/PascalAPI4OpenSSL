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

unit MainUnit;

{$IFDEF FPC}
{$mode Delphi}
{$ENDIF}
{$IFDEF MSWINDOWS}
{$DEFINE WINDOWS}
{$ENDIF}

interface

uses
  Classes , SysUtils, {$IFDEF FPC}CustApp,{$ENDIF} GenerateHeaderUnit,
  GenerateSmartLoad , GenerateJITUnit;

const
  DefaultOutputPrefix = 'OpenSSL_';
  DefaultCopyFilePrefix = '';


type
  {$if not declared(TCustomApplication)}
  {$DEFINE LOCAL_TCUSTOMAPP}
  TCustomApplication = class(TComponent)
  private
    FTitle: string;
  protected
    procedure DoRun; virtual; abstract;
  public
    function Exename: string;
    procedure Run;
    procedure Terminate;
    property Title: string read FTitle write FTitle;
  end;
  {$IFEND}


  { OpenSSLAPICodeGenerator }

  OpenSSLAPICodeGenerator = class(TCustomApplication)
  private
    procedure WriteLine(line: string);
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner : TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  end;


implementation

resourcestring
  RSOBadOutputDir        = 'Output Directory (%s) does not exist!';
  RSOUnrecognisedOption  = 'Unrecognised option: %s';
  RSONoGeneratorSelected = 'Go Unit file generator selected';
  RSOLastArgument        = 'Last argument must either be a valid directory or file path';
  RSOFileNotFound        = 'File not found - %s';
  RSONoFixUps              = 'WARNING: no uses clause fix ups';

{$IFDEF LOCAL_TCUSTOMAPP}
function TCustomApplication.Exename: string;
begin
  Result := ParamStr(0);
end;

procedure TCustomApplication.Run;
begin
  try
    DoRun;
  except on E: Exception do
    writeln(E.Message);
  end;
end;

procedure TCustomApplication.Terminate;
begin

end;
{$ENDIF}

{ OpenSSLAPICodeGenerator }

procedure OpenSSLAPICodeGenerator.WriteLine(line : string);
begin
  writeln(line);
end;

procedure OpenSSLAPICodeGenerator.DoRun;
var
  SmartGen: boolean;
  JitGen: boolean;
  OutputDir: string;
  Source: string;
  SourceIsDir: boolean;
  i: integer;
  OutputPrefix: string;
  CopyFilePrefix: string;
  Generator: TGenerateAPIUnit;
  CopyFiles: TStrings;
begin
  writeln('OpenSSL Pascal API Header Generator');
  writeln('Copyright © MWA Software 2024');

  SmartGen := true;
  JitGen := false;
  OutputDir := GetCurrentDir;
  Source := '';
  SourceIsDir := false;
  OutputPrefix := DefaultOutputPrefix;
  CopyFilePrefix := DefaultCopyFilePrefix;

  CopyFiles := TStringList.Create;
  try
   try
    // quick check parameters
    i := 1;
    while i <= ParamCount do
    begin
      if ParamStr(i) = '-h' then
      begin
        WriteHelp;
        Terminate;
        Exit;
      end;

      if (ParamStr(i) = '-s') or (ParamStr(i) = '--smart') then
        SmartGen := true
      else
      if (ParamStr(i) = '-j') or (ParamStr(i) = '--jit') then
      begin
        SmartGen := false;
        JitGen := true;
      end
      else
      if (ParamStr(i) = '-p') or (ParamStr(i) = '--prefix') then
      begin
        Inc(i);
        OutputPrefix := ParamStr(i);
      end
      else
      if (ParamStr(i) = '-P') or (ParamStr(i) = '--includeFilePrefix') then
      begin
        Inc(i);
        CopyFilePrefix := ParamStr(i);
      end
      else
      if (ParamStr(i) = '-o') or (ParamStr(i) = '--output') then
      begin
        Inc(i);
        OutputDir := ExcludeTrailingPathDelimiter(ParamStr(i));
        if not DirectoryExists(OutputDir) and
            not CreateDir(OutputDir) then
             raise Exception.CreateFmt(RSOBadOutputDir,[OutputDir]);
      end
      else
      if (ParamStr(i) = '-a') or (ParamStr(i) = '--includeFile') then
      begin
        Inc(i);
        if not DirectoryExists(ParamStr(i)) and not FileExists(ParamStr(i)) then
          raise Exception.CreateFmt(RSOFileNotFound,[ParamStr(i)]);
        CopyFiles.Add(ParamStr(i));
      end
      else
      if i = ParamCount then
      begin
        if DirectoryExists(ParamStr(i)) then
        begin
          Source := ExcludeTrailingPathDelimiter(ParamStr(i));
          SourceIsDir := true;
        end
        else
        if FileExists(ParamStr(i)) then
          Source := ParamStr(i)
        else
          raise Exception.CreateFmt(RSOLastArgument,[ParamStr(i)]);
      end
      else
        raise Exception.CreateFmt(RSOUnrecognisedOption,[ParamStr(i)]);
      Inc(i);
    end;

    if Source = '' then
    begin
      WriteHelp;
      Terminate;
      Exit;
    end;

    if SmartGen then
      Generator := TGenerateSmartLoadUnit.Create
    else
    if JitGen then
      Generator := TGenerateJITUnit.Create
    else
      raise Exception.Create(RSONoGeneratorSelected);

    Generator.UnitPrefix := OutputPrefix;
    Generator.CopyFilePrefix := CopyFilePrefix;

    try
      Generator.WriteLine := WriteLine;
      if SourceIsDir then
      begin
        Generator.GenerateHeaderUnitFromDir(Source,OutputDir,CopyFiles);
      end
      else
      begin
        writeln(RSONoFixUps);
        Generator.GenerateHeaderUnitFrom(Source,OutputDir);
      end;
    finally
      Generator.Free;
    end;

   except on E: Exception do
     writeln('Error: ', E.Message);
   end;
  finally
    CopyFiles.Free;
  end;
  {$IFDEF DEBUG}
  {$IFDEF WINDOWS}
  write('Press Enter to Exit');
  readln;
  {$ENDIF}
  {$ENDIF}
  Terminate;
end;

constructor OpenSSLAPICodeGenerator.Create(TheOwner : TComponent);
begin
  inherited Create(TheOwner);
  {$IFDEF FPC}
  StopOnException := True;
  {$ENDIF}
end;

destructor OpenSSLAPICodeGenerator.Destroy;
begin
  inherited Destroy;
end;

procedure OpenSSLAPICodeGenerator.WriteHelp;
begin
  writeln('Usage: ' , ExtractFileName(ExeName) , ' [-h] [--smart] [--jit] [-p <output unit prefix] '+
          '[-a <include file(s)][-P <include file prefix>][-o <output directory>] <file or directory>');
  writeln('Options:');
  writeln('-h            Help: outputs this message');
  writeln('-s|--smart    Generate smart load strategy (default)');
  writeln('-j|--jit      Generator Just In Time Load strategy');
  writeln('-p|--prefix   Output unit name prefix');
  writeln('-P|--includedFilePrefix Include File (unitname) Prefix (overrides unit name prefix');
  writeln('-a|--includeFiles   includefile(s) source dir');
  writeln;
end;

end.

