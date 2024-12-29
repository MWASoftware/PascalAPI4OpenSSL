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

unit GenerateSmartLoad;

{$IFDEF FPC}
{$mode Delphi}
{$ENDIF}

(*
  This unit defines the class TGenerateSmartLoadUnit as a subclass of the abstract
  class TGenerateAPIUnit. TGenerateSmartLoadUnit adds Load and Unload procedures
  to the output API unit in respect of dynamic library loading and initialises each
  API function variable to nil.

  At load time, each API function is loaded in turn. If it fails to load then the
  API function variable is set to the address of a compatibility function, if one exists
  or to an error function that raises a customised exception.

  The exception is when the API function is marked up as "Allow nil" when a failure to
  load results in the corresponding API function variable remaining nil. It is the
  responsiblity of the caller to check for nil values and handle them appropriately.

  The Unload procedure simply resets each API function variable back to nil.
*)

interface

uses
  Classes , SysUtils, GenerateHeaderUnit, APIFileReader, ProgramConstants;

type

  { TGenerateSmartLoadUnit }

  TGenerateSmartLoadUnit = class(TGenerateAPIUnit)
  private
    FHasLoadFunction: boolean;
    FHasUnLoadFunction: boolean;
  protected
    procedure AddErrorFunctions(S : TStrings); override;
    procedure AddDynamicLoadInit(S: TStrings); override;
    procedure AddLoadFunctions(S : TStrings); override;
    procedure AddUnLoadFunctions(S : TStrings); override;
    procedure Clear; override;
    function GetInitialiser(funcProc: IFuncProcInfo): string; override;
    function GetImplementationUses: string; override;
    procedure AddNoLegacyConditionals(S : TStrings; funcProc: IFuncProcInfo; var InLegacy: boolean);
    function PreLoadFunction(funcProc: IFuncProcInfo): boolean; virtual;

  end;

implementation

uses Tokeniser;


{ TGenerateSmartLoadUnit }

procedure TGenerateSmartLoadUnit.AddErrorFunctions(S : TStrings);
var i: integer;
    funcProc: IFuncProcInfo;
    ErrorImplementation: TStrings;
begin
  ErrorImplementation := TStringList.Create;
  try
  with InterfaceSection do
  begin
    for i := 0 to Count - 1 do
    begin
      if TObject(Items[i]) is IFuncProcInfo then
        funcProc :=  TObject(Items[i]) as IFuncProcInfo
      else
      begin
        if TObject(Items[i]) is TDirective then
        with TObject(Items[i]) as TDirective do
        begin
          ErrorImplementation.Add('{$' + Name + Condition + '}')
        end;
        continue;
      end;

      if PreLoadFunction(funcProc) then
      with funcProc do
      if not AllowNil then
      begin
        with ErrorImplementation do
        begin
          if (CompatibilityFunctions.IndexOf(ProcName) <> -1) then
            Add('{$IFDEF ' + NoLegacySupportSymbol + '}');
          Add(GetDeclaration('ERROR_'));
          Add('begin');
          Add('  ' + ErrorExceptionClassName + '.RaiseException(''' + procName + ''');');
          Add('end;');
          if (CompatibilityFunctions.IndexOf(ProcName) <> -1) then
            Add('{$ENDIF} { End of ' + NoLegacySupportSymbol + '}');
          Add('');
        end;
      end;
    end;
    if ErrorImplementation.Count > 0 then
    begin
      S.Add('');
      S.Add('{$WARN  NO_RETVAL OFF}');
      S.AddStrings(ErrorImplementation);
      S.Add('{$WARN  NO_RETVAL ON}');
    end;
  end;

  finally
    ErrorImplementation.Free;
  end;
end;

procedure TGenerateSmartLoadUnit.AddDynamicLoadInit(S : TStrings);
begin
  S.Add('{$IFNDEF ' + StaticLinkModel + '}');
  if FHasLoadFunction then
    S.Add('Register_SSLLoader(@Load);');
  if FHasUnLoadFunction then
    S.Add('Register_SSLUnloader(@Unload);');
  S.Add('{$ENDIF}');
end;

procedure TGenerateSmartLoadUnit.AddLoadFunctions(S : TStrings);
var i: integer;
    funcProc: IFuncProcInfo;
    LoadFunction: TStrings;
    Inlegacy: boolean;
    InConditional: boolean;
begin
  InConditional := false;
  Inlegacy := false;
  LoadFunction := TStringList.Create;
  try
    LoadFunction.Add('procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);');
    LoadFunction.Add('var FuncLoadError: boolean;');
    LoadFunction.Add('begin');

    with InterfaceSection do
      for i := 0 to Count - 1 do
      begin
        if TObject(Items[i]) is IFuncProcInfo then
          funcProc :=  TObject(Items[i])  as IFuncProcInfo
        else
        begin
          if TObject(Items[i]) is TDirective then
          begin
            with TObject(Items[i]) as TDirective do
              LoadFunction.Add('{$' + Name + Condition + '}');
            InConditional := true;
          end;
          continue;
        end;

        if PreLoadFunction(funcProc) then
        with funcProc do
        begin
          FHasLoadFunction := true;
          AddNoLegacyConditionals(LoadFunction,funcProc,InLegacy);
          LoadFunction.Add('  ' + procName + ' := Load' + LibName + 'Function(''' + procName + ''');');
          LoadFunction.Add('  FuncLoadError := not assigned(' + procName + ');');
          LoadFunction.Add('  if FuncLoadError then');
          LoadFunction.Add('  begin');
          if CompatibilityFunctions.IndexOf(procName) <> -1 then
          begin
            if not InLegacy then
              LoadFunction.Add('{$IFNDEF ' + NoLegacySupportSymbol + '}');
            LoadFunction.Add('    ' + procName + ' := @COMPAT_' + procName + ';');
            if not InLegacy then
              LoadFunction.Add('{$ELSE}');
          end;
          if not AllowNil then
          begin
            if not InLegacy then
              LoadFunction.Add('    ' + procName + ' :=  @ERROR_' + procName + ';');
            if Introduced then
            begin
              LoadFunction.Add('    if LibVersion < ' + procName + '_introduced then');
              LoadFunction.Add('      FuncLoadError := false;');
            end;
            if Removed then
            begin
              LoadFunction.Add('    if ' + procName + '_removed <= LibVersion then');
              LoadFunction.Add('      FuncLoadError := false;');
            end;

            if Introduced or Removed then
            begin
              LoadFunction.Add('    if FuncLoadError then');
              LoadFunction.Add('      AFailed.Add(''' + procName + ''');');
            end;
          end

          else
            LoadFunction.Add('    {Don''t report allow nil failure}');
//            LoadFunction.Add('    AFailed.Add(''' + procName + ''');');
          if (CompatibilityFunctions.IndexOf(procName) <> -1) and not InLegacy then
            LoadFunction.Add('{$ENDIF}');
          LoadFunction.Add('  end;');

          if InConditional then
          begin
            AddNoLegacyConditionals(LoadFunction,nil,InLegacy);
            InConditional := false;
          end;
          LoadFunction.Add('');
        end;
      end;
    AddNoLegacyConditionals(LoadFunction,nil,InLegacy);
    LoadFunction.Add('end;');

    if FHasLoadFunction then
      S.AddStrings(LoadFunction);

  finally
    LoadFunction.Free;
  end;
end;

procedure TGenerateSmartLoadUnit.AddUnLoadFunctions(S : TStrings);
var i: integer;
    UnLoadFunction: TStrings;
    funcProc: IFuncProcInfo;
    InLegacy: boolean;
    InConditional: boolean;
begin
  InLegacy := false;
  InConditional := false;
  UnLoadFunction := TStringList.Create;
  try
    UnLoadFunction.Add('');
    UnLoadFunction.Add('procedure UnLoad;');
    UnLoadFunction.Add('begin');
    with InterfaceSection do
    for i := 0 to Count - 1 do
    begin
      if TObject(Items[i]) is TDirective then
      with TObject(Items[i]) as TDirective do
      begin
        UnLoadFunction.Add('{$' + Name + Condition + '}');
        InConditional := true;
      end
      else
      if TObject(Items[i]) is IFuncProcInfo then
      begin
        funcProc :=  TObject(Items[i]) as IFuncProcInfo;
        FHasUnLoadFunction := true;
        AddNoLegacyConditionals(UnLoadFunction,funcProc,InLegacy);
        with funcProc do
        if IsFunction then
          UnLoadFunction.Add('  ' + ProcName + ' := ' + GetInitialiser(funcProc) + ';')
        else
          UnLoadFunction.Add('  ' + ProcName + ' := ' + GetInitialiser(funcProc) + ';');
        if InLegacy and InConditional then
          AddNoLegacyConditionals(UnLoadFunction,nil,InLegacy);
        InConditional := false;
      end
    end;
    AddNoLegacyConditionals(UnLoadFunction,nil,InLegacy);
    UnLoadFunction.Add('end;');
    if FHasUnLoadFunction then
      S.AddStrings(UnLoadFunction);
  finally
    UnLoadFunction.Free
  end;
end;

procedure TGenerateSmartLoadUnit.Clear;
begin
  inherited Clear;
  FHasUnLoadFunction := false;
  FHasLoadFunction := false;
end;

function TGenerateSmartLoadUnit.GetInitialiser(funcProc : IFuncProcInfo
  ) : string;
begin
  Result := 'nil';
end;

function TGenerateSmartLoadUnit.GetImplementationUses : string;
var i: integer;
    Separator: string;
begin
  Result := '';
  Separator := '';
  for i := 0 to length(ImplementationSectionUses) - 1 do
  begin
    Result := Result + Separator + DoFixUp(ImplementationSectionUses[i]);
    Separator := ',' + LineEnding + '     ';
  end;
end;

procedure TGenerateSmartLoadUnit.AddNoLegacyConditionals(S : TStrings;
  funcProc : IFuncProcInfo; var InLegacy : boolean);
begin
  if assigned(funcProc) and funcProc.Removed and not InLegacy then
  begin
    S.Add('{$IFNDEF ' + NoLegacySupportSymbol + '}');
    InLegacy := true;
  end;
  if (not assigned(funcProc) or not funcProc.Removed) and InLegacy then
  begin
    S.Add('{$ENDIF} //of ' + NoLegacySupportSymbol);
    InLegacy := false;
  end;
end;

function TGenerateSmartLoadUnit.PreLoadFunction(funcProc : IFuncProcInfo
  ) : boolean;
begin
  Result := true;
end;

end.

