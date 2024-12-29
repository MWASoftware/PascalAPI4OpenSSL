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

unit APIFileReader;

{ $DEFINE SHOWTOKENS}

{$IFDEF FPC}
{$mode Delphi}
{$ENDIF}

{$if not defined(FPC) and declared(CompilerVersion) and (CompilerVersion >= 20)}
{$DEFINE CHAR_IS_WIDECHAR}   //Delphi 2009 or later
{$ifend}

(*  The class TAPIFileReader uses a TPascalTokeniser to read an input stream
   containing a Pascal unit and to analyse it in to its main sections:

   *  UnitHeader                - everything before the "interface"
   *  InterfaceSection          - everything between "interface" and "implementation"
   *  ImplementationSection     - everything between "implementation" and the end of unit/initialization/finalization
   *  InitializationSection     - everything between "Initialization" and end of unit/finalization, if any
   *  FinalizationSection       - everything between "Finalization" and end of unit, if any.

   The interface and implmentation sections are of type TList, while others are TStrings,
   comprising the lines of text read in.

   The two lists are lists of classes derived from TStrings and each is a typed list
   of the lines of text read in, representing the Uses clause, const, type and var clauses
   and any plaintext (comments) that does not naturally belong in a typed TStrings.

   The interface and implementation lists may also include objects of the classes:

   * TDirective                - Compiler directives (e.g. {$IFDEF ..}) found between
                                 other clauses. Note that directives within (e.g.)
                                 a type declaration are not separately listed and
                                 are instead part of that clause.

   * TFunction                 - Function Declarations. In the implementation section
                                 these include the function body.

   * TProcedure                - Procedure Declarations. In the implementation section
                                 these include the procedure body.

   Note: procedure and function declarations found between the special comments
   '{passthrough} and {/helper_functions} are listed as the contents of
   THelperFunctions - another TStrings derived class.

   Call ReadAPIHeaderFile to read in a Pascal Unit and analyse it into its sections.
   When ReadAPIHeaderFile returns, the object's properties may be used to process
   the sections.

   The input file must be either a single byte ANSI character set or UTF8. On platforms
   where type char = WideChar, the TAPIFileReader will transliterate to WideChar.

   A single instance of this class can be used to analyse successive source files
   as long as "Clear" is called between each successive call to ReadAPIHeaderFile.
*)

interface

uses
  Classes , SysUtils, Tokeniser, ProgramConstants;

const

  sLibName = 'UnitLibName';

type
  TUsesClause = class(TStringList);
  TConstClause = class(TStringList);
  TTypeClause = class(TStringList);
  TVarClause = class(TStringList);
  TPlainText = class(TStringList);
  THelperFunctions = class(TStringList);

  TRelease = array [0..2] of integer;

//  IFuncProcInfo = interface   {Had to rewrite as abstract class for Delphi compatibility}
  IFuncProcInfo = class
  protected
    function GetFunctionBody: TStrings; virtual; abstract;
  public
    function GetAllowNil: boolean; virtual; abstract;
    function GetExternalDeclaration: string; virtual; abstract;
    function GetDeclaration(prefix : string='') : string; virtual; abstract;
    function GetIntroducedIn: string; virtual; abstract;
    function GetRemovedIn: string; virtual; abstract;
    function GetProcName: string;virtual; abstract;
    function GetProcHeader: string; virtual; abstract;
    function GetParamNames: TStrings; virtual; abstract;
    function GetResultType: string; virtual; abstract;
    function GetVarDeclaration(initialiser : string) : string; virtual; abstract;
    function HasVarargs: boolean; virtual; abstract;
    function Introduced: boolean; virtual; abstract;
    function IntroducedVersion: string;virtual; abstract;
    function IsFunction: boolean; virtual; abstract;
    function Removed: boolean; virtual; abstract;
    function RemovedVersion: string; virtual; abstract;
    property AllowNil: boolean read GetAllowNil;
    property ProcName: string read GetProcName ;
    property ProcHeader: string read GetProcHeader;
    property ResultType: string read GetResultType;
    property FunctionBody: TStrings read GetFunctionBody;
  end;

  { TDirective }

  TDirective = class
  private
    FCondition : string;
    FName : string;
  public
    constructor Create(aName, aCondition: string);
    property Name: string read FName write FName;
    property Condition: string read FCondition write FCondition;
  end;

  TWriteLine = procedure (line: string) of object;


  { TAPIFileReader }

  TAPIFileReader = class
  private type

    { TAPIFileTokeniser }

    TAPIFileTokeniser = class(TPascalTokeniser)
    private
      FSource: TStream;
      procedure SkipBOM;
    protected
      function GetChar: Char; override;
    public
      constructor Create(source: TStream);
    end;

  private type
    {The Major States represent the major sub-divisions of a Pascal Unit}
    TMajorStates = (mjUnitHeader,         {Initial state - everything before the interface section}
                    mjInterface,          {Entered when "interface" reserved word found}
                    mjImplementation,     {Entered when "implementation" reserved word found}
                    mjInitialization,     {Entered when "initialization" reserved word found}
                    mjFinalization        {Entered when "finalization" reserved word found}
                    );

    {The minor states are used to process const, type, var and procedure/function declarations}
    TMinorStates = (msIdle,
                    msExpectingUnit,
                    msExpectingUnitName,
                    msExpectingStatementTerminator,
                    msExpectingBlockTerminator,
                    msUsesClause,
                    msConst,
                    msConstDefined,
                    msType,
                    msTypeDefined,
                    msClassType,
                    msVar,
                    msVarDefined,
                    msLocalVar,
                    msLocalConst,
                    msLocalType,
                    msHelpers,
                    msExpectingProcName,
                    msInProcFuncHeader,
                    msExpectingParamName,
                    msExpectingParamType,
                    msExpectingResultType,
                    msIgnoreWhiteSpace,
                    msProcFuncBody,
                    msEmbeddedProcFunc
                    );
  private
    FTokeniser: TPascalTokeniser;
    FMajorState: TMajorStates;
    FMinorState: TMinorStates;
    FLine: string;              {used to assemble current line by concatenating successive symbols from input stream}
    FPassThru: string;          {use to copy input text with unitname processing}
    FLines: TStrings;           {Each line is added to this list - may change on state change}
    FCurrentList: TList;        {A newly created element is added to this list.
                                 In the case of recursive elements, FCurrentList is set to
                                 the newly created list. Also changes when major state changes}

    {As input file is parsed, the declarations and definitions are added to each section.
     Simple sections are just TStrings, while sections that can comprise may elements
     are lists.}
    FFinalizationSection : TStrings;
    FImplementationSection : TList;
    FInitializationSection : TStrings;
    FInterfaceSection : TList;
    FUnitHeader : TStrings;
    FBlockCount: integer;
    FBracketCount: integer;
    FUnitName: string;
    FWriteLine : TWriteLine;
    FEndOfUnit: boolean;
    procedure AddClause(clause: TObject);
    procedure AddLines(multilineText: string);
    function CurrentClause: TObject;
    function HasCurrentClause: boolean; inline;
    procedure ParseError(const err : string);
    function ProcessComment(commentText: string): boolean;
    function ProcessFunctionStatus(commentText: string): boolean;
    procedure ProcessToken(token: TPascalTokens; T: TPascalTokeniser);
    procedure SetMajorState(NewState: TMajorStates);
    function StateFromCurrentClause : TMinorStates;
    procedure SaveCurrentLine;
    procedure StateError;
  protected
    FGetUnitNamesPass: boolean;
    procedure AddText(S: TStrings; aText: string);
    procedure DoWriteLine(line: string); inline;
    function DoFixUp(useUnit: string): string; virtual;
    function GetUnitName(aUnitName: string):string; virtual;
    procedure PeekSaveLine(var aLine: string); virtual;
    procedure SetExternalLibName(aLibName: string); virtual; abstract;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Clear; virtual;
    procedure ReadAPIHeaderFile(filename: string);
    property UnitHeader: TStrings read FUnitHeader;
    property InterfaceSection: TList read FInterfaceSection;
    property ImplementationSection: TList read FImplementationSection;
    property InitializationSection: TStrings read FInitializationSection;
    property FinalizationSection: TStrings read FFinalizationSection;
    property UnitName: string read FUnitName;
    property Writeline: TWriteLine read FWriteLine write FWriteLine;
  end;

implementation

uses {$IFDEF FPC} RegExpr {$ELSE}
  {$IF declared(CompilerVersion) and (CompilerVersion >= 22)}
  RegularExpressions
  {$IFEND}
{$ENDIF};

resourcestring
  RSOParseError             = 'Parse Error at Line %d, character %d, %s';
  RSONoCurrentClause        = 'No Current Element available';
  RSOBadHelperFunctionStart = 'Helper Functions cannot be declared here';
  RSOBadHelperFunctionEnd   = 'Invalid location for completing Helper Functinos';
  RSOUnexpectedResultType   = 'Unexpected function result type syntax';
  RSONoCurrentList          = 'No current list available';
  RSOStateError             = 'Syntax Error at Line %d, Character %d, State = %d, Minor = %d';
  RSOTextBeyondEndOfUnit    = 'Text beyond end of unit';
  RSOUnexpectedBegin        = 'Unexpected "begin"';
  RSOUnexpectedEnd          = 'Unexpected "end"';
  RSONotaFunction           = 'Only a function can have a result type';
  RSOUnexpectedUnitHeader   = 'Unexpected Unit Header';
  RSOInputFrom              = 'Reading %s';
  RSOUnexpectedClass        = 'Unexpected Class';
  RSOUnexpectedTry          = 'Unexpected Try';
  RSOUnexpectedConstructor  = 'Unextected constructor/destructor';

type
    { TFuncProc }

    TFuncProc = class(IFuncProcInfo)
    private
      FAllowNil : boolean;
      FIntroducedIn : TRelease;
      FProcHeader : string;
      FProcName : string;
      FRemoved : TRelease;
      FParamNames: TStrings;
      FVarargs: boolean;
      FFunctionBody: TStrings;
    protected
      procedure AddParamName(paramName: string);
      procedure SetIntroducedIn(v1,v2,v3: integer);
      procedure SetRemovedIn(v1,v2,v3: integer);
      procedure SetVarargs(aValue: boolean);
      function GetFunctionBody: TStrings; override;
    public
      function GetAllowNil: boolean; override;
      function GetProcName: string; override;
      function GetProcHeader: string; override;
      function GetParamNames: TStrings; override;
      function GetIntroducedIn: string; override;
      function GetRemovedIn: string; override;
      function Removed: boolean; override;
      function Introduced: boolean; override;
      function IntroducedVersion: string; override;
      function IsFunction: boolean; override;
      function RemovedVersion: string; override;
      function GetExternalDeclaration: string; override;
      function GetDeclaration(prefix : string='') : string; override;
      function GetVarDeclaration(initialiser : string) : string; override;
      function HasVarargs: boolean; override;
    public
      constructor Create;
      destructor Destroy; override;
    public
      property AllowNil: boolean read FAllowNil write FAllowNil;
      property ProcName: string read FProcName write FProcName;
      property ProcHeader: string read FProcHeader write FProcHeader;
      property IntroducedIn: TRelease read FIntroducedIn;
      property RemovedIn: TRelease read FRemoved;
    end;

    { TProcedure }

    TProcedure = class(TFuncProc)
      function GetResultType: string; override;
    end;

    { TFunction }

    TFunction = class(TFuncProc)
    private
      FResultType : string;
    public
      function IsFunction: boolean; override;
      function GetResultType: string; override;
      property ResultType: string read GetResultType write FResultType;
    end;

    { TExternalProcedure }

    TExternalProcedure = class(TProcedure);

    TExternalFunction = class(TFunction);



{ TProcedure }

function TProcedure.GetResultType : string;
begin
  raise Exception.Create(RSONotaFunction);;
end;

{ TFunction }

function TFunction.IsFunction : boolean;
begin
  Result := true;
end;

function TFunction.GetResultType : string;
begin
  Result := FResultType;
end;

{ TDirective }

constructor TDirective.Create(aName , aCondition : string);
begin
  inherited Create;
  FName := aName;
  FCondition := aCondition;
end;

{ TFuncProc }

function TFuncProc.GetAllowNil : boolean;
begin
  Result := FAllowNil;
end;

function TFuncProc.GetProcName : string;
begin
  Result := FProcName;
end;

function TFuncProc.GetProcHeader : string;
begin
  Result := FProcHeader;
end;

function TFuncProc.GetParamNames : TStrings;
begin
  Result := FParamNames;
end;

function TFuncProc.GetIntroducedIn : string;
const
  sIntoVersion = 'introduced %d.%d.%d';
begin
  Result := Format(sIntoVersion,[IntroducedIn[0],IntroducedIn[1],IntroducedIn[2]]);
end;

function TFuncProc.GetRemovedIn : string;
const
  sRemovedVersion = 'removed %d.%d.%d';
begin
  Result := Format(sRemovedVersion,[RemovedIn[0],RemovedIn[1],RemovedIn[2]]);
end;

function TFuncProc.HasVarargs : boolean;
begin
  Result := FVarargs;
end;

procedure TFuncProc.SetVarargs(aValue : boolean);
begin
  FVarargs := aValue;
end;

function TFuncProc.GetFunctionBody : TStrings;
begin
  Result := FFunctionBody;
end;

procedure TFuncProc.SetIntroducedIn(v1 , v2 , v3 : integer);
begin
  FIntroducedIn[0] := v1;
  FIntroducedIn[1] := v2;
  FIntroducedIn[2] := v3;
end;

procedure TFuncProc.SetRemovedIn(v1 , v2 , v3 : integer);
begin
  FRemoved[0] := v1;
  FRemoved[1] := v2;
  FRemoved[2] := v3;
end;

function TFuncProc.Removed : boolean;
begin
  Result := not ((RemovedIn[0] = 0) and (RemovedIn[1] = 0) and (RemovedIn[2] = 0));
  if Result then
  begin
    Result := RemovedIn[0] <= BaseMajorVersion;
    if not Result then
      Result := (RemovedIn[0] = BaseMajorVersion) and (RemovedIn[1] <= BaseMinorVersion);
    if not Result then
      Result := (RemovedIn[0] = BaseMajorVersion) and (RemovedIn[1] = BaseMinorVersion) and (RemovedIn[2] <= BasePatchVersion);
  end;
//  writeln('Removed:',ProcName,',',Result);
end;

function TFuncProc.Introduced : boolean;
begin
  Result := not ((IntroducedIn[0] = 0) and (IntroducedIn[1] = 0) and (IntroducedIn[2] = 0));
  if Result then
  begin
    Result := IntroducedIn[0] > BaseMajorVersion;
    if not Result then
      Result := (IntroducedIn[0] = BaseMajorVersion) and (IntroducedIn[1] > BaseMinorVersion);
    if not Result then
      Result := (IntroducedIn[0] = BaseMajorVersion) and (IntroducedIn[1] = BaseMinorVersion) and (IntroducedIn[2] > BasePatchVersion);
  end;
//  writeln('Introduced:',ProcName,' ',Result);
end;

const
  sVersionString = '((((((byte(%d) shl 8) or byte(%d)) shl 8) or byte(%d)) shl 8) or byte(0)) shl 4';

function TFuncProc.IntroducedVersion : string;
begin
  if (IntroducedIn[0] = 0) and (IntroducedIn[1] = 0) and (IntroducedIn[2] = 0) then
    Result := ''
  else
    Result :=  Format(sVersionString,[IntroducedIn[0],
                                    IntroducedIn[1],
                                    IntroducedIn[2]]) ;
end;

function TFuncProc.IsFunction : boolean;
begin
  Result := false;
end;

function TFuncProc.RemovedVersion : string;
begin
  if (RemovedIn[0] = 0) and (RemovedIn[1] = 0) and (RemovedIn[2] = 0) then
    Result := ''
  else
    Result :=  Format(sVersionString,[RemovedIn[0],
                                    RemovedIn[1],
                                    RemovedIn[2]]);
end;

procedure TFuncProc.AddParamName(paramName : string);
begin
  FParamNames.Add(Trim(paramName));
end;

constructor TFuncProc.Create;
begin
  inherited;
  FParamNames := TStringList.Create;
  FFunctionBody := TStringList.Create;
end;

destructor TFuncProc.Destroy;
begin
  if FParamNames <> nil then
    FParamNames.Free;
  if FFunctionBody <> nil then
    FFunctionBody.Free;
  inherited Destroy;
end;

function TFuncProc.GetExternalDeclaration : string;
begin
  if IsFunction then
    Result := 'function '
  else
    Result := 'procedure ';
  Result := Result + ProcName + ProcHeader;
  if IsFunction then
    Result := Result + ': ' + (self as TFunction).ResultType;
  if not Removed then
  Result := Result + '; cdecl';
  if HasVarArgs then
    Result := Result + ' varargs';
  Result := Result + ';';
  if Introduced or Removed then
  begin
    Result := Result + ' {';
    if Introduced then
      Result := Result + GetIntroducedIn + ' ';
    if Removed then
      Result := Result + GetRemovedIn;
    if AllowNil then
      Result := Result + ' allow_nil';
    Result := Result + '}';
  end;
end;

function TFuncProc.GetDeclaration(prefix : string) : string;
begin
  if IsFunction then
    Result := 'function '
  else
    Result := 'procedure ';
  Result := Result + prefix + ProcName + ProcHeader;
  if IsFunction then
    Result := Result + ': ' + (self as TFunction).ResultType;
  Result := Result + '; cdecl;';
  if Introduced or Removed then
  begin
    Result := Result + ' {';
    if Introduced then
      Result := Result + GetIntroducedIn + ' ';
    if Removed then
      Result := Result + GetRemovedIn;
    if AllowNil then
      Result := Result + ' allow_nil';
    Result := Result + '}';
  end;
end;

function TFuncProc.GetVarDeclaration(initialiser : string) : string;
begin
  Result := ProcName + ': ';
  if IsFunction then
    Result := Result + 'function '
  else
    Result := Result + 'procedure ';
  Result := Result + ProcHeader;
  if IsFunction then
    Result := Result + ': ' + (self as TFunction).ResultType;
  Result := Result + ';';
  Result := Result + ' cdecl';
  if HasVarArgs then
    Result := Result + ' varargs';
  if Initialiser <> '' then
    Result := Result + ' = ' + initialiser;
  Result := Result + ';';
  if Introduced or Removed then
  begin
    Result := Result + ' {';
    if Introduced then
      Result := Result + GetIntroducedIn + ' ';
    if Removed then
      Result := Result + GetRemovedIn;
    if AllowNil then
      Result := Result + ' allow_nil';
    Result := Result + '}';
  end;
end;


{ TAPIFileReader.TAPIFileTokeniser }

procedure TAPIFileReader.TAPIFileTokeniser.SkipBOM;
var C1, C2, C3: AnsiChar;
begin
  FSource.Read(C1,1);
  if C1 = #$EF then
  begin
    FSource.Read(C2,1);
    if C2 = #$BB then
    begin
      FSource.Read(C3,1);
      if C3 = #$BF then
        Exit;
    end;
  end;
  FSource.Position := 0; {reset stream}
end;

function TAPIFileReader.TAPIFileTokeniser.GetChar : Char;
{$IFNDEF CHAR_IS_WIDECHAR}
begin
  if FSource.Position = FSource.Size then
    Result := #0
  else
    FSource.Read(Result,1);
end;

{$ELSE}
var C: AnsiChar;
    MultiByteChar: array [0..4] of AnsiChar;
begin
  if FSource.Position = FSource.Size then
    C := #0
  else
    FSource.Read(C,1);
  if ord(C) and $E0 = $C0 then {Multibyte UTF8 character}
  begin
    FillChar(MultiByteChar,sizeof(MultiByteChar),0);
    MultiByteChar[0] := C;
    FSource.Read(MultiByteChar[1],1);
    if ord(C) and $F0 = $E0 then
      FSource.Read(MultiByteChar[2],1);
    if ord(C) and $F8 = $F0 then
      FSource.Read(MultiByteChar[3],1);
    UTF8ToUnicode(@Result,@MultiByteChar,1);
  end
  else
    Result := WideChar(C);
end;
{$ENDIF}

constructor TAPIFileReader.TAPIFileTokeniser.Create(source : TStream);
begin
  inherited Create;
  FSource := source;
end;

{ TAPIFileReader }

procedure TAPIFileReader.AddClause(clause : TObject);
begin
  if (FLines <> nil) and (FLine <> '') then
    SaveCurrentLine;
  if FCurrentList <> nil then
    FCurrentList.Add(clause)
  else
    ParseError(RSONoCurrentList);

  if clause is TStrings then
    FLines := clause as TStrings
  else
  if clause is IFuncProcInfo then
    FLines := (clause as IFuncProcInfo).FunctionBody
  else
    FLines := nil;
end;

procedure TAPIFileReader.AddLines(multilineText : string);
begin
  if FLines = nil then
    AddClause(TPlainText.Create);
  AddText(FLines,multilineText);
end;

function TAPIFileReader.CurrentClause: TObject;
begin
  if HasCurrentClause then
    Result := TObject(FCurrentList[FCurrentList.Count-1])
  else
  case FMajorState of
  mjUnitHeader,
  mjInitialization,
  mjFinalization:
    Result := FLines;
  else
    ParseError(RSONoCurrentClause);
  end;
end;

procedure TAPIFileReader.AddText(S: TStrings; aText: string);
var TextSnippet: TStrings;
begin
  {$IFDEF FPC}
  S.AddText(aText);
  {$ELSE}
  TextSnippet := TStringList.Create;
  try
    TextSnippet.Text := aText;
    S.AddStrings(TextSnippet);
  finally
    TextSnippet.Free;
  end;
  {$ENDIF}
end;

procedure TAPIFileReader.DoWriteLine(line : string);
begin
  if assigned(FWriteLine) then
    WriteLine(line);
end;

function TAPIFileReader.HasCurrentClause : boolean;
begin
  Result := (FCurrentList <> nil) and (FCurrentList.Count > 0);
end;

procedure TAPIFileReader.ParseError(const err : string);
begin
  raise Exception.CreateFmt(RSOParseError,[FTokeniser.LineNo,FTokeniser.CharNo,err]);
end;

function TAPIFileReader.ProcessComment(commentText : string) : boolean;
begin
  Result := true;
  commentText := Trim(commentText);
  if Pos('passthrough',commentText) = 1 then
    case FMajorState of
    mjInterface,
    mjImplementation:
      begin
        AddClause(THelperFunctions.Create);
        FMinorState := msHelpers;
      end;
    else
      ParseError(RSOBadHelperFunctionStart);
    end
  else
  if (FMinorState = msHelpers) and (Pos('/passthrough',commentText) = 1) then
    case FMajorState of
    mjInterface,
    mjImplementation:
      begin
        SaveCurrentLine;
        FLines := nil;
        FMinorState := msIdle;
      end
    else
      ParseError(RSOBadHelperFunctionEnd);
    end
  else
  if CurrentClause is TFuncProc then
    Result := ProcessFunctionStatus(commentText)
  else
    Result := false;
end;

const
  rxIntroducedMatch = 'introduced *([0-9]+)\.([0-9]+)\.([0-9]+)';
  rxRemovedMatch    = 'removed *([0-9]+)\.([0-9]+)\.([0-9]+)';
  rxAllowNilMatch = 'allow_nil';

  rxIntroduced = '^ *' + rxIntroducedMatch + ' *(' + rxRemovedMatch + '|) *(' + rxAllowNilMatch + '|) *$';
  rxRemoved    = '^ *(' + rxIntroducedMatch + '|)' + rxRemovedMatch + ' *(' + rxAllowNilMatch + '|) *$';
  rxAllowNil   =  '^ *' + rxAllowNilMatch;

{$IF declared(TRegexpr)} //FPC
function TAPIFileReader.ProcessFunctionStatus(commentText : string) : boolean;
var RegexObj: TRegExpr;
begin
  RegexObj := TRegExpr.Create;
  try
    RegexObj.ModifierG := false; {turn off greedy matches}
    RegexObj.ModifierI := true; {case insensitive match}
    RegexObj.Expression := rxIntroduced;
    Result := RegexObj.Exec(commentText);
    if Result then
    begin
      with CurrentClause as TFuncProc do
      begin
        SetIntroducedIn(StrToInt(RegexObj.Match[1]),
                        StrToInt(RegexObj.Match[2]),
                        StrToInt(RegexObj.Match[3]));
        if RegexObj.Match[4] <> '' then
        begin
          SetRemovedIn(StrToInt(RegexObj.Match[5]),
                       StrToInt(RegexObj.Match[6]),
                       StrToInt(RegexObj.Match[7]));
        end;
        AllowNil := RegexObj.Match[8] = rxAllowNilMatch;
 //       writeln(ProcName,' I:',IntroducedVersion,' R:',RemovedVersion,' ',AllowNil,' ',RegexObj.Match[8],' ',RegexObj.SubExprMatchCount);
      end
    end
    else
    begin
      RegexObj.Expression := rxRemoved;
      Result := RegexObj.Exec(commentText);
      if Result then
      begin
        with CurrentClause as TFuncProc do
        begin
          if RegexObj.Match[1]  <> '' then
          begin
            SetIntroducedIn(StrToInt(RegexObj.Match[2]),
                            StrToInt(RegexObj.Match[3]),
                            StrToInt(RegexObj.Match[4]));
          end;
          SetRemovedIn(StrToInt(RegexObj.Match[5]),
                     StrToInt(RegexObj.Match[6]),
                     StrToInt(RegexObj.Match[7]));
          AllowNil := RegexObj.Match[8] = rxAllowNilMatch;
//          writeln(ProcName,' I:',IntroducedVersion,' R:',RemovedVersion,' ',AllowNil,' ',RegexObj.Match[8],' ',RegexObj.SubExprMatchCount);
        end;
      end
      else
      begin
        RegexObj.Expression := rxAllowNil;
        Result := RegexObj.Exec(commentText);
        with CurrentClause as TFuncProc do
          AllowNil := Result;
      end;
    end;
  finally
    RegexObj.Free;
  end;
end;
{$ELSE}      //Delphi
function TAPIFileReader.ProcessFunctionStatus(commentText : string): boolean;
var RegexRec: TRegEx;
    Match: TMatch;
begin
  RegexRec := TRegEx.Create(rxIntroduced);
    Match := RegexRec.Match(commentText);
    Result := Match.Success;
    if Result then
      with CurrentClause as TFuncProc do
      begin
        SetIntroducedIn(StrToInt(Match.Groups[1].Value),
                        StrToInt(Match.Groups[2].Value),
                        StrToInt(Match.Groups[3].Value));
        if Match.Groups[4].Value <> '' then
        begin
          SetRemovedIn(StrToInt(Match.Groups[5].Value),
                       StrToInt(Match.Groups[6].Value),
                       StrToInt(Match.Groups[7].Value));
        end;
        AllowNil := Match.Groups[8].Value = rxAllowNilMatch
      end;
  if not Result then
  begin
    RegexRec := TRegEx.Create(rxRemoved);
      Match := RegexRec.Match(commentText);
      Result := Match.Success;
      if Result then
        with CurrentClause as TFuncProc do
        begin
          if Match.Groups[1].Value <> '' then
          begin
            SetIntroducedIn(StrToInt(Match.Groups[2].Value),
                            StrToInt(Match.Groups[3].Value),
                            StrToInt(Match.Groups[4].Value));
         end;
         SetRemovedIn(StrToInt(Match.Groups[5].Value),
                      StrToInt(Match.Groups[6].Value),
                      StrToInt(Match.Groups[7].Value));
         AllowNil := Match.Groups[8].Value = rxAllowNilMatch ;
      end
  end;
  if not Result then
  begin
    RegexRec := TRegEx.Create(rxAllowNil);
    Match := RegexRec.Match(commentText);
    Result := Match.Success;
    (CurrentClause as TFuncProc).AllowNil := Result;
  end;
end;
{$IFEND}

function TAPIFileReader.StateFromCurrentClause: TMinorStates;
var
  clause: TObject;
begin
  clause := CurrentClause;
  if clause is TConstClause then
    Result := msConst
  else
  if clause is TTypeClause then
    Result := msType
  else
  if clause is TVarClause then
    Result := msVar
  else
    Result := msIdle;
end;

procedure TAPIFileReader.ProcessToken(token : TPascalTokens; T : TPascalTokeniser
  );
var InputTokenText: string;
begin
 InputTokenText := T.TokenText;
 {$IFDEF SHOWTOKENS}
 {$IFDEF FPC}
 writeln(FTokeniser.LineNo,': ',FMajorstate,':',FMinorState,' (',FBracketCount,',',FBlockCount,') ',token,' ',T.TokenText);
 {$ELSE}
 writeln(FTokeniser.LineNo,': ',ord(FMajorstate),':',ord(FMinorState),' (',FBracketCount,',',FBlockCount,') ',Ord(token),' ',T.TokenText);
 {$ENDIF}
 {$ENDIF}
 try
  if (FMinorState = msIgnoreWhiteSpace) then
  begin
    if CurrentClause is TFuncProc then
    begin
      if FMajorState = mjInterface then
        FMinorState:= msIdle
      else
        FMinorState := msProcFuncBody;
    end;
  end;

  case token of
  pstSpace:
    if FMinorState <> msIgnoreWhiteSpace then
      FLine := FLine + T.TokenText;

  pstUnit:
    begin
      FLine := FLine + T.TokenText;
      if FMinorState = msExpectingUnit then
        FMinorState := msExpectingUnitName
      else
        ParseError(RSOUnexpectedUnitHeader);
    end;

  pstFunction:
    case FMinorState of
    msIdle, msConstDefined, msTypeDefined, msVarDefined:
    begin
      SaveCurrentLine;
      case FMajorState of
      mjInterface:
        begin
          AddClause(TExternalFunction.Create);
          FMinorState := msExpectingProcName;
        end;
      mjImplementation:
        begin
          AddClause(TFunction.Create);
          FMinorState := msExpectingProcName;
        end;
      end;
    end;

    msProcFuncBody:
      FMinorState := msEmbeddedProcFunc;

    else
      FLine := FLine + T.TokenText;
    end;

  pstProcedure:
    case FMinorState of
    msIdle, msConstDefined, msTypeDefined, msVarDefined:
    begin
      SaveCurrentLine;
      case FMajorState of
      mjInterface:
        begin
          AddClause(TExternalProcedure.Create);
          FMinorState := msExpectingProcName;
        end;
      mjImplementation:
        begin
          AddClause(TProcedure.Create);
          FMinorState := msExpectingProcName;
        end;
      end;
    end;

    msProcFuncBody:
      FMinorState := msEmbeddedProcFunc;

    else
      FLine := FLine + T.TokenText;
    end;

  pstConstructor,
  pstDestructor:
  begin
    if (FBlockCount = 0) and (FMinorState in [msIdle, msConstDefined, msTypeDefined, msVarDefined]) then
    begin
      SaveCurrentLine;
      if  FMajorState <>  mjImplementation then
        ParseError(RSOUnexpectedConstructor);

      AddClause(TProcedure.Create);
      FMinorState := msExpectingProcName;
    end
    else
      FLine := FLine + T.TokenText;
  end;


  pstVarargs:
    if (FMinorState = msIdle) and (CurrentClause is TFuncProc) then
      (CurrentClause as TFuncProc).SetVarArgs(true)
    else
      StateError;

  pstConst:
    begin
      case FMinorState of
        msIdle, msTypeDefined, msVarDefined:
        begin
          AddClause(TConstClause.Create);
          FMinorState := msConst;
        end;

        msLocalConst,msLocalType,msLocalVar,
        msProcFuncBody:
          FMinorState := msLocalConst;
      end;

      FLine := FLine + T.TokenText;
    end;

  pstType:
    begin
      case FMinorState of
        msIdle, msConstDefined, msVarDefined:
        begin
          AddClause(TTypeClause.Create);
          FMinorState := msType;
        end;

        msLocalConst,msLocalType,msLocalVar,
        msProcFuncBody:
          FMinorState := msLocalConst;
      end;
      FLine := FLine + T.TokenText;
    end;

  pstVar:
    begin
      case FMinorState of
        msIdle, msConstDefined, msTypeDefined:
        begin
          AddClause(TVarClause.Create);
          FMinorState := msVar;
        end;

        msLocalConst,msLocalType,msLocalVar,
        msProcFuncBody:
          FMinorState := msLocalConst;
      end;

      FLine := FLine + T.TokenText;
    end;

  pstSemiColon:
    {Look for end of current function/procedure header}
    begin
      case FMinorState of
      msExpectingStatementTerminator:
        begin
          if not (CurrentClause is TFuncProc) then
          begin
            FLine := FLine + T.TokenText;
            FMinorState := msIdle
          end
          else
          begin
            FMinorState := msIgnoreWhiteSpace;
            FLine := '';
          end;
        end;

      msExpectingBlockTerminator:
        begin
          FLine := FLine + T.TokenText;
          FMinorState := msIdle
        end;

      msInProcFuncHeader:
        if FBracketCount = 0 then
          FMinorState := msIgnoreWhiteSpace
        else
          FLine := FLine + T.TokenText;

      msExpectingParamType:
        begin
          if FBracketCount > 0 then
            FMinorState := msExpectingParamName;
          FLine := FLine + T.TokenText;
        end;

      msVar:
        begin
          if (FBlockCount = 0) and (FBracketCount = 0) then
            FMinorState := msVarDefined;
          FLine := FLine + T.TokenText;
        end;

      msType:
        begin
          if (FBlockCount = 0) and (FBracketCount = 0) then
            FMinorState := msTypeDefined;
          FLine := FLine + T.TokenText;
        end;

      msConst:
        begin
          if (FBlockCount = 0) and (FBracketCount = 0) then
            FMinorState := msConstDefined;
          FLine := FLine + T.TokenText;
        end;

      msUsesClause:
        begin
          FMinorState := msIdle;
          FLine := FLine + T.TokenText;
        end;

      else
        FLine := FLine + T.TokenText;
      end;
    end;

  pstOpenBracket:
    begin
      if (FBracketCount = 0) and (FMinorState = msInProcFuncHeader) then
        FMinorState := msExpectingParamName;
      Inc(FBracketCount);
      FLine := FLine + T.TokenText;
    end;

  pstCloseBracket:
    begin
      FLine := FLine + T.TokenText;
      Dec(FBracketCount);
      if (FBracketCount = 0) and (FMinorState = msExpectingParamType) then
      begin
        if CurrentClause is IFuncProcInfo then
        with CurrentClause as IFuncProcInfo do
        begin
          if IsFunction then
            FMinorState := msInProcFuncHeader
          else
            FMinorState := msExpectingStatementTerminator;
          (CurrentClause as TFuncProc).ProcHeader := FLine;
          FLine := '';
        end
        else
          StateError;
      end;
    end;

  pstColon:
    {Look for function return type}
    begin
      if FMinorState = msInProcFuncHeader then
      begin
        if FBracketCount = 0 then
        begin
          if CurrentClause is TFunction {Includes subclass TExternalFunction } then
            FMinorState := msExpectingResultType
          else
            ParseError(RSOUnexpectedResultType);
          Exit;
        end
        else
        if FBracketCount = 1 then
          FMinorState := msExpectingParamType;
      end;
      FLine := FLine + T.TokenText;
    end;

  pstComma:
    begin
      if FMinorState = msInProcFuncHeader then
        FMinorState := msExpectingParamName;
      FLine := FLine + T.TokenText;
    end;

  pstIdentifier:
    case FMinorState of
    msIdle:
      begin
        FMinorState := StateFromCurrentClause;
        FLine := FLine + T.TokenText;
      end;

    msExpectingUnitName:
      begin
        FUnitName := GetUnitName(Trim(T.TokenText));
        FLine := FLine + FUnitName;
        InputTokenText := FUnitName; {Modify unitname for passthrough}
        FMinorState := msExpectingStatementTerminator;
      end;

    msExpectingProcName:
      begin
        (CurrentClause as TFuncProc).ProcName := Trim(T.TokenText);
        FLine := '';
        FMinorState := msInProcFuncHeader;
      end;

    msExpectingParamName:
      begin
        (CurrentClause as TFuncProc).AddParamName(T.TokenText);
        FMinorState := msInProcFuncHeader;
        FLine := FLine + T.TokenText;
      end;

    msExpectingResultType:
      begin
        (CurrentClause as TFunction).ResultType := T.TokenText;
        FMinorState := msExpectingStatementTerminator;
      end;

    msConstDefined:
      begin
        FMinorState := msConst;
        FLine := FLine + T.TokenText;
      end;

    msTypeDefined:
      begin
        FMinorState := msType;
        FLine := FLine + T.TokenText;
      end;

    msVarDefined:
      begin
        FMinorState := msVar;
        FLine := FLine + T.TokenText;
      end;

    msUsesClause:
      begin
        InputTokenText :=  DoFixUp(T.TokenText); {Modify used unitname}
        FLine := FLine + InputTokenText;
      end;

    else
        FLine := FLine + T.TokenText;
    end;

  pstBegin:
  case FMajorState of
    mjImplementation,
    mjInitialization,
    mjFinalization:
      begin
        FLine := FLine + T.TokenText;
        Inc(FBlockCount);
        if FMinorState in [msLocalConst,msLocalType,msLocalVar] then
          FMinorState := msProcFuncBody;
      end;

    else
      ParseError(RSOUnexpectedBegin);
  end;

  pstRecord:
    begin
      if FMinorState in [msType,msVar,msTypeDefined, msVarDefined] then
        Inc(FBlockCount);
      FLine := FLine + T.TokenText;
    end;

  pstClass:
    begin
      case FMinorState of
      msType, msTypeDefined:
        begin
          FMinorState := msClassType;
          Inc(FBlockCount);
        end;
      msVar, msVarDefined:
        ParseError(RSOUnexpectedClass);
      end;
      FLine := FLine + T.TokenText;
    end;


  pstCase:
    begin
      if not (FMinorState in [msType,msVar]) then
        Inc(FBlockCount);
      FLine := FLine + T.TokenText;
    end;

  pstTry:
    begin
      if FMinorState in [msProcFuncBody,msEmbeddedProcFunc, msHelpers] then
      begin
        Inc(FBlockCount);
        FLine := FLine + T.TokenText;
      end
      else
        ParseError(RSOUnexpectedTry);
    end;

  pstEnd:
  begin
    Dec(FBlockCount);
    case FMinorState of
    msClassType:
      FMinorState := msTypeDefined;
    msHelpers, msType,msVar,msTypeDefined, msVarDefined: {ok};
    msProcFuncBody:
      if FBlockCount = 0 then
        FMinorState := msExpectingBlockTerminator;
    msEmbeddedProcFunc:
      if FBlockCount = 0 then
        FMinorState := msProcFuncBody;
    else
      ParseError(RSOUnexpectedEnd);
    end;
    FLine := FLine + T.TokenText;
  end;

  pstEndOfUnit:
    begin
      FEndOfUnit := true;
      InputTokenText := 'end.'
    end;

  pstInterface:
    if FMajorState = mjUnitHeader then
    begin
      SetMajorState(mjInterface);
      FLine := FLine + T.TokenText;
    end
    else
    if FMinorState = msType then
    begin
      Inc(FBlockCount);
      FLine := FLine + T.TokenText
    end
    else
      StateError;

  pstUses:
    begin
      if FMinorState <> msIdle then
        StateError;
      AddClause(TUsesClause.Create);
      FLine := T.TokenText;
      FMinorState := msUsesClause;
    end;

  pstImplementation:
    case FMajorState of
    mjInterface:
    begin
      if FMinorState in [msConstDefined, msTypeDefined, msVarDefined] then
        FMinorState := msIdle;
      SetMajorState(mjImplementation);
      FLine := FLine + T.TokenText;
    end
    else
      StateError;
    end;

  pstInitialization:
    case FMajorState of
    mjImplementation:
      SetMajorState(mjInitialization)
    else
      StateError;
    end;

  pstFinalization:
    case FMajorState of
    mjImplementation,
    mjInitialization:
      SetMajorState(mjFinalization)
    else
      StateError;
    end;

  pstComment:
    if not (FMinorState in [msIdle,msHelpers,msTypeDefined,msVarDefined,msConstDefined])
                                 or not ProcessComment(T.TokenText) then
    begin
      InputTokenText :=  '{' + T.TokenText + '}';
      FLine := FLine + InputTokenText;
    end;

  pstCommentLine:
    begin
      InputTokenText :=  '//' + T.TokenText + LineEnding;  ;
      FLine := FLine +  InputTokenText;
    end;

  pstComment2:
    begin
      InputTokenText := '(*' + T.TokenText + '*)';
      FLine := FLine + InputTokenText;
    end;

  pstDirective:
    begin
      if T.Directive = sLibName then
        SetExternalLibName(T.TokenText)
      else
      begin
        if not (FMajorState in [mjUnitHeader, mjFinalization, mjInitialization])
                                   and (FMinorState in [msIdle,msConstDefined,msTypeDefined,msVarDefined])
                                   and not (CurrentClause is TUsesClause) then
          AddClause(TDirective.Create(T.Directive, T.TokenText)) ;
        InputTokenText := '{$' + T.Directive + T.TokenText + '}';
        FLine := FLine + InputTokenText;
      end;
    end;

  pstQuotedString:
    begin
      InputTokenText :=  '''' + T.TokenText + '''';
      FLine := FLine + InputTokenText;
    end;

  pstDoubleQuotedString:
    begin
      InputTokenText := '"' + T.TokenText + '"';
      FLine := FLine +  InputTokenText;
    end;

  pstEOL:
    begin
      if FMinorState <> msIgnoreWhiteSpace then
        SaveCurrentLine;
      PeekSaveLine(FPassThru);
      FPassThru := '';
    end;

  else
    FLine := FLine + T.TokenText;
  end;

 finally
  if token <> pstEOL then
    FPassThru := FPassThru + InputTokenText;
 end;
end;

procedure TAPIFileReader.SetMajorState(NewState : TMajorStates);
begin
  if not (FMinorState in [msIdle,msConst,msVar,msType]) then
    StateError;
  if NewState <> mjUnitHeader then  {ignore if initialising}
    SaveCurrentLine;
  FMajorState := NewState;
  FLines := nil;
  FCurrentList := nil;
  FMinorState := msIdle;
  case FMajorState of
  mjUnitHeader:
    begin
      FMinorState := msExpectingUnit;
      FLines := UnitHeader;
    end;

  mjInterface:
    FCurrentList := InterfaceSection;

  mjImplementation:
    FCurrentList := ImplementationSection;

  mjInitialization:
    FLines := InitializationSection;

  mjFinalization:
    FLines := FinalizationSection;
  end;
end;

procedure TAPIFileReader.SaveCurrentLine;
begin
  if FLines = nil then
    AddClause(TPlainText.Create);

  FLines.Add(FLine);
  FLine := '';
end;

procedure TAPIFileReader.StateError;
begin
  {$IFDEF FPC}
  raise Exception.CreateFmt(RSOStateError,[FTokeniser.LineNo, FTokeniser.CharNo,FMajorState,FMinorState]);
  {$ELSE}
  raise Exception.CreateFmt(RSOStateError,[FTokeniser.LineNo, FTokeniser.CharNo,ord(FMajorState),Ord(FMinorState)]);
  {$ENDIF}
end;

function TAPIFileReader.DoFixUp(useUnit : string) : string;
begin
  Result := useUnit;
end;

function TAPIFileReader.GetUnitName(aUnitName : string) : string;
begin
  Result := aUnitName;
end;

procedure TAPIFileReader.PeekSaveLine(var aLine : string);
begin

end;

constructor TAPIFileReader.Create;
begin
  inherited Create;
  FFinalizationSection := TStringList.Create;
  FImplementationSection := TList.Create;
  FInitializationSection := TStringList.Create;
  FInterfaceSection := TList.Create;
  FUnitHeader := TStringList.Create;
  Clear;
end;

destructor TAPIFileReader.Destroy;
begin
  Clear;
  if FFinalizationSection <> nil then FFinalizationSection.Free;
  if FImplementationSection <> nil then FImplementationSection.Free;
  if FInitializationSection <> nil then FInitializationSection.Free;
  if FInterfaceSection <> nil then FInterfaceSection.Free;
  if FUnitHeader <> nil then FUnitHeader.Free;
  inherited Destroy;
end;

procedure TAPIFileReader.Clear;
var i : integer;
begin
  if FTokeniser <> nil then
    FreeAndNil(FTokeniser);
  FMajorState := mjUnitHeader;
  FMinorState := msIdle;
  FLine := '';
  FPassThru := '';
  FLines := nil;
  FCurrentList := nil;
  FBlockCount := 0;
  FBracketCount := 0;
  FUnitName := '';
  FEndOfUnit := false;
  FFinalizationSection.Clear;
  FInitializationSection.Clear;
  FUnitHeader.Clear;
  with FInterfaceSection do
  begin
    for i := 0 to Count - 1 do
      TObject(Items[i]).Free;
    Clear;
  end;
  with FImplementationSection do
  begin
    for i := 0 to Count - 1 do
      TObject(Items[i]).Free;
    Clear;
  end;
end;

procedure TAPIFileReader.ReadAPIHeaderFile(filename : string);
var F: TFileStream;
  token: TPascalTokens;
begin
  Clear;
  DoWriteLine(Format(RSOInputFrom,[filename]));
  F := TFileStream.Create(filename,fmOpenRead);
  try
    FTokeniser := TAPIFileTokeniser.Create(F);
    try
      SetMajorState(mjUnitHeader);
      token := FTokeniser.GetNextToken;
      while token <> pstEOF  do
      begin
        if FEndOfUnit and not (token in [pstSpace, pstEOL]) then
          ParseError(RSOTextBeyondEndOfUnit);
        ProcessToken(token,FTokeniser);
        token := FTokeniser.GetNextToken;
        if FGetUnitNamesPass and (FUnitName <> '') then
          Exit; {got what we want}
      end;
      if token = pstEOF then
      begin
        SaveCurrentLine;
        PeekSaveLine(FPassThru);
      end;
    finally
      FreeAndNil(FTokeniser);
    end;
  finally
    F.Free;
  end;
end;

end.

