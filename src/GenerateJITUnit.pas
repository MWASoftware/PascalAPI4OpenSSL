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

unit GenerateJITUnit;

{$IFDEF FPC}
{$mode Delphi}
{$ENDIF}

interface

(*  The TGenerateJITUnit is a subclass of TGenerateSmartLoadUnit and is used to
    customise the API function load strategy to a "Just in Time" approach.

    Here, instead of loading every API function at load time, only API functions
    marked as "allow nil" are loaded. The remaining API functions are initialised
    (at compile time) to a specialised "load function". Thus, the first time a
    given API function is called, it is the load function that is invoked and not
    the API call.

    The load function attempts to load the actual API function call and if successful
    set ths API function variable to the actual API function call. It then calls the
    API function on the caller's behalf and returns any result. The next time the
    API function is called, the actual function is called.

    If the actual API function call fails to load then a compatibility function is
    used instead, if one exists, otherwise an exception is raised.

    The advantages of this strategy over "smart loading" are:

    - quicker library loading
    - Only the used API calls are loaded.
*)

uses
  Classes , SysUtils, GenerateHeaderUnit, APIFileReader, GenerateSmartLoad,
  ProgramConstants;

type

  { TGenerateJITUnit }

  TGenerateJITUnit = class(TGenerateSmartLoadUnit)
  protected
    procedure AddDynamicInterfaceSection(S : TStrings; firstFuncProc : integer); override;
    procedure AddDynamicImplementationSection(S: TStrings; firstFuncProc: integer); override;
    function GetInitialiser(funcProc : IFuncProcInfo) : string; override;
    function PreLoadFunction(funcProc: IFuncProcInfo): boolean; override;
  end;

implementation


{ TGenerateJITUnit }

procedure TGenerateJITUnit.AddDynamicInterfaceSection(S : TStrings;
  firstFuncProc : integer);
var i: integer;
    needsComment: boolean;
    InLegacy: boolean;
    funcProc: IFuncProcInfo;
begin
  needsComment := true;
  InLegacy := false;
  with InterfaceSection do
  for i := firstFuncProc to Count - 1 do
  begin
    if TObject(Items[i]) is TDirective then
    with TDirective(Items[i]) do
      S.Add('{$' + Name + Condition + '}')
    else
    if TObject(Items[i]) is IFuncProcInfo then
    begin
      funcProc := TObject(Items[i]) as IFuncProcInfo;
      with funcProc do
      if not AllowNil then
      begin
        if needsComment then
        begin
          S.Add('');
          S.Add('{Declare external function initialisers - should not be called directly}');
          S.Add('');
          needsComment := false;
        end;
        AddNoLegacyConditionals(S,funcProc,InLegacy);
        if IsFunction then
          S.Add('function Load_' + ProcName + ProcHeader + ': ' + ResultType + '; cdecl;')
        else
          S.Add('procedure Load_' + ProcName + ProcHeader + '; cdecl;');
      end;
    end;
  end;
  AddNoLegacyConditionals(S,nil,InLegacy);
  S.Add('');
  inherited AddDynamicInterfaceSection(S , firstFuncProc);
end;

procedure TGenerateJITUnit.AddDynamicImplementationSection(S : TStrings;
  firstFuncProc : integer);
var i: integer;
    funcProc: IFuncProcInfo;
    InLegacy: boolean;
begin
  inherited AddDynamicImplementationSection(S,firstFuncProc);
  InLegacy := false;
  {Create an initialiser function for each dynamic API variable listed in TAPIInitializer}
  with InterfaceSection do
  for i := firstFuncProc to Count - 1 do
  begin
    if TObject(Items[i]) is TDirective then
    with TDirective(Items[i]) do
      S.Add('{$' + Name + Condition + '}')
    else
    if TObject(Items[i]) is IFuncProcInfo  then
    begin
      funcProc := TObject(Items[i]) as IFuncProcInfo;
      if not PreLoadFunction(funcProc) then
      with funcProc do
      begin
        AddNoLegacyConditionals(S,funcProc,InLegacy);
        if IsFunction then
          S.Add('function Load_' + ProcName + ProcHeader + ': ' + ResultType + '; cdecl;')
        else
          S.Add('procedure Load_' + ProcName + ProcHeader + '; cdecl;');

        S.Add('begin');
        S.Add('  ' + procName + ' := Load' + LibName + 'Function(''' + ProcName + ''');');
        S.Add('  if not assigned(' + procName + ') then');
        if CompatibilityFunctions.IndexOf(ProcName) <> -1 then
        begin
          if not InLegacy then
            S.Add('{$IFNDEF ' + NoLegacySupportSymbol + '}');
          S.Add('    ' + procName + ' := @COMPAT_' + ProcName + ';');
          if not InLegacy then
          begin
            S.Add('{$ELSE}');
            S.Add('    ' + ErrorExceptionClassName + '.RaiseException(''' + ProcName + ''');');
            S.Add('{$ENDIF} { End of ' + NoLegacySupportSymbol + '}');
          end;
        end
        else
          S.Add('    ' + ErrorExceptionClassName + '.RaiseException(''' + ProcName + ''');');
        if IsFunction then
          S.Add('  Result := ' + procName + '(' + GetParamNames.CommaText + ');')
        else
          S.Add('  ' + procName + '(' + GetParamNames.CommaText + ');');

        S.Add('end;');
        S.Add('');
      end;
    end;
  end;
  AddNoLegacyConditionals(S,nil,InLegacy);
end;

function TGenerateJITUnit.GetInitialiser(funcProc : IFuncProcInfo) : string;
begin
  with funcProc do
  if AllowNil then
    Result := 'nil'
  else
    Result := 'Load_' + ProcName;
end;

function TGenerateJITUnit.PreLoadFunction(funcProc : IFuncProcInfo) : boolean;
begin
  with funcProc do
    Result := AllowNil;
end;

end.

