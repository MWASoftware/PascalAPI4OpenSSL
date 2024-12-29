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

unit Tokeniser;

{$IFDEF FPC}
{$mode Delphi}
{$ENDIF}

{ This unit defines the TPascalTokeniser class. This is an abstract class that
  processes an input stream of type char and outputs a stream of tokens/symbols.
  The input stream is assumed to be Pascal source code files. The output tokens
  are not intended to be a complete in the sense of the symbol stream required
  by a Pascal compiler but are sufficient for an API code generator.

  The abstract function GetChar: char is overridden in order to read from the input
  stream. This function reads from the stream one character at a time.

  When the type char = AnsiChar, the stream should be predominantly ASCII characters.
  However, the tokeniser should be transparent to UTF8 or extended single byte
  characters provided these are in string literals or comments.

  When the type char = WideChar then the stream is a stream of UTF-16 characters.
  As above the tokeniser should be transparent to four byte characters provided
  these are in string literals or comments.

  The output token stream is accessed by successive calls to "GetNextToken". The
  property TokenText provides any text associated with the returned symbol.

}

interface

uses
  Classes , SysUtils;

const
  CR   = #13;
  LF   = #10;
  TAB  = #9;
  NULL_TERMINATOR = #0;

  {Delphi Compatibility - FPC already defines these}

  {$if not declared(DirectorySeparator)}
  DirectorySeparator = '\';
  {$ifend}
  {$IF not declared(LineEnding)}
  const
    {$IFDEF UNIX}
    LineEnding = #$0A;
    {$ELSE}
    LineEnding = #$0D#$0A;   //must be Delphi on Windows
    {$ENDIF}
  {$ifend}


  ValidIdentifierChars = ['A'..'Z','a'..'z','0'..'9','_'];

type
  TPascalTokens = (
  pstSpace,
  pstSemiColon,
  pstPlaceholder,
  pstSingleQuotes,
  pstDoubleQuotes,
  pstBackslash,
  pstComma,
  pstPeriod,
  pstEquals,
  pstOtherCharacter,
  pstIdentifier,
  pstDoubleQuotedString,
  pstNumberString,
  pstString,
  pstParam,
  pstQuotedParam,
  pstColon,
  pstComment,
  pstComment2, {uses (*..*) as comment delimiters}
  pstCommentLine,
  pstDirective,
  pstQuotedString,
  pstAsterisk,
  pstForwardSlash,
  pstOpenSquareBracket,
  pstCloseSquareBracket,
  pstOpenBracket,
  pstCloseBracket,
  pstOpenBrace,
  pstCloseBrace,
  pstDollar,
  pstPipe,
  pstMinus,
  pstLT,
  pstGT,
  pstCR,
  pstEOL,
  pstEOF,
  pstEndOfUnit,
  pstInit,

  {reserved words}
  pstUnit,
  pstFunction,
  pstProcedure,
  pstConstructor,
  pstDestructor,
  pstBegin,
  pstEnd,
  pstCase,
  pstInterface,
  pstUses,
  pstImplementation,
  pstInitialization,
  pstFinalization,
  pstConst,
  pstType,
  pstVar,
  pstVarargs,
  pstOut,
  pstTry,
  pstRecord,
  pstClass
  );

  TPascalReservedWords = pstUnit..pstClass;

  const

  {limit set of Pascal Reserved words - these are the only ones of interest to us}
  pascalReservedWords: array [TPascalReservedWords] of string = (
  'UNIT',
  'FUNCTION',
  'PROCEDURE',
  'CONSTRUCTOR',
  'DESTRUCTOR',
  'BEGIN',
  'END',
  'CASE',
  'INTERFACE',
  'USES',
  'IMPLEMENTATION',
  'INITIALIZATION',
  'FINALIZATION',
  'CONST',
  'TYPE',
  'VAR',
  'VARARGS',
  'OUT',
  'TRY',
  'RECORD',
  'CLASS'
  );

  type

  { TPascalTokeniser }

  TPascalTokeniser = class
  private
    const
      TokenQueueMaxSize = 64;
    type
      TLexState = (stDefault, stInCommentLine,
                   stInComment,  (*uses {..} as comment delimiters*)
                   stInComment2, {uses (*..*) as comment delimiters}

                   stInDirective, stInDirectiveType,
                   stSingleQuoted, stDoubleQuoted, stInIdentifier, stInNumeric);

      TTokenQueueItem = record
                          token: TPascalTokens;
                          text: string;
                        end;
      TTokenQueueState = (tsHold, tsRelease);

  private
    FLastChar: Char;
    FState: TLexState;
    FSkipNext: boolean;
    function GetNext: TPascalTokens;

    {The token Queue is available for use by descendents so that they can
     hold back tokens in order to lookahead by token rather than just a single
     character}

  private
    FCharNo : integer;
    FDirective : string;
    FLineNo : integer;
    FTokenQueue: array[0..TokenQueueMaxSize] of TTokenQueueItem;
    FQueueState: TTokenQueueState;
    FQFirst: integer;  {first and last pointers first=last => queue empty}
    FQLast: integer;
    FEOF: boolean;
    procedure PopQueue(var token: TPascalTokens);
  protected
    FString: string;
    FNextToken: TPascalTokens;
    procedure Assign(source: TPascalTokeniser); virtual;
    function GetChar: Char; virtual; abstract;
    function TokenFound(var token: TPascalTokens): boolean; virtual;
    function InternalGetNextToken: TPascalTokens; virtual;
    procedure Reset; virtual;
    function ReadCharacters(NumOfChars: integer): string;
    function FindReservedWord(w: string; var token: TPascalTokens): boolean;

    {Token stack}
    procedure QueueToken(token: TPascalTokens; text:string); overload;
    procedure QueueToken(token: TPascalTokens); overload;
    procedure ResetQueue; overload;
    procedure ResetQueue(token: TPascalTokens; text:string); overload;
    procedure ResetQueue(token: TPascalTokens); overload;
    procedure ReleaseQueue(var token: TPascalTokens); overload;
    procedure ReleaseQueue; overload;
    function GetQueuedText: string;
    procedure SetTokenText(text: string);

  public
    const
        DefaultTerminator = ';';
  public
    constructor Create;
    destructor Destroy; override;
    function GetNextToken: TPascalTokens;
    property EOF: boolean read FEOF;
    property TokenText: string read FString;
    property Directive: string read FDirective;
    property LineNo: integer read FLineNo;
    property CharNo: integer read FCharNo;
  end;

implementation

resourcestring
  RSOTokenQueueUnderflow = 'Error: Token stack underflow';
  RSOTokenQueueOverflow = 'Error: Token stack overflow';
  rsstringliteralEOL    = 'Error: string Literal exceeds End of Line at Line %d, character %d';
  rsDoublestringliteralEOL    = 'Error: Double string Literal exceeds End of Line at Line %d, character %d';

function TPascalTokeniser.GetNext: TPascalTokens;
var C: char;
begin
  if EOF then
    Result := pstEOF
  else
  begin
    C := GetChar;
    Inc(FCharNo);
    case C of
    #0:
      Result := pstEOF;
    ' ',TAB:
      Result := pstSpace;
    '0'..'9':
      Result := pstNumberstring;
    ';':
      Result := pstSemiColon;
    '?':
      Result := pstPlaceholder;
    '|':
      Result := pstPipe;
    '"':
      Result := pstDoubleQuotes;
    '''':
      Result := pstSingleQuotes;
    '/':
      Result := pstForwardSlash;
    '\':
      Result := pstBackslash;
    '*':
      Result := pstAsterisk;
    '(':
      Result := pstOpenBracket;
    ')':
      Result := pstCloseBracket;
    ':':
      Result := pstColon;
    ',':
      Result := pstComma;
    '.':
      Result := pstPeriod;
    '=':
      Result := pstEquals;
    '[':
      Result := pstOpenSquareBracket;
    ']':
      Result := pstCloseSquareBracket;
    '{':
      Result := pstOpenBrace;
    '}':
      Result := pstCloseBrace;
    '-':
      Result := pstMinus;
    '<':
      Result := pstLT;
    '>':
      Result := pstGT;
    '$':
      Result := pstDollar;
    CR:
      Result := pstCR;
    LF:
      begin
        Inc(FLineNo);
        FCharNo := 0;
        Result := pstEOL;
      end;
    else
      if C in ValidIdentifierChars then
        Result := pstIdentifier
      else
        Result := pstOtherCharacter;
    end;
    FLastChar := C
  end;
  FNextToken := Result;
end;

procedure TPascalTokeniser.PopQueue(var token: TPascalTokens);
begin
  if FQFirst = FQLast then
    raise Exception.Create(RSOTokenQueueUnderflow);
  token := FTokenQueue[FQFirst].token;
  FString := FTokenQueue[FQFirst].text;
  Inc(FQFirst);
  if FQFirst = FQLast then
    FQueueState := tsHold;
end;

procedure TPascalTokeniser.Assign(source : TPascalTokeniser);
begin
  FString := source.FString;
  FNextToken := source.FNextToken;
  FTokenQueue := source.FTokenQueue;
  FQueueState := source.FQueueState;
  FQFirst := source.FQFirst;
  FQLast := source.FQLast;
end;

function TPascalTokeniser.TokenFound(var token: TPascalTokens): boolean;
begin
  Result := (FState = stDefault);
  if Result and (token = pstIdentifier)  then
    FindReservedWord(FString,token);
end;

procedure TPascalTokeniser.QueueToken(token: TPascalTokens; text: string);
begin
  if FQLast > TokenQueueMaxSize then
    raise Exception.Create(RSOTokenQueueOverflow);
  FTokenQueue[FQLast].token := token;
  FTokenQueue[FQLast].text := text;
  Inc(FQLast);
end;

procedure TPascalTokeniser.QueueToken(token: TPascalTokens);
begin
  QueueToken(token,TokenText);
end;

procedure TPascalTokeniser.ResetQueue;
begin
  FQFirst := 0;
  FQLast := 0;
  FQueueState := tsHold;
end;

procedure TPascalTokeniser.ResetQueue(token: TPascalTokens; text: string);
begin
  ResetQueue;
  QueueToken(token,text);
end;

procedure TPascalTokeniser.ResetQueue(token: TPascalTokens);
begin
  ResetQueue;
  QueueToken(token);
end;

procedure TPascalTokeniser.ReleaseQueue(var token: TPascalTokens);
begin
  FQueueState := tsRelease;
  PopQueue(token);
end;

procedure TPascalTokeniser.ReleaseQueue;
begin
  FQueueState := tsRelease;
end;

function TPascalTokeniser.GetQueuedText: string;
var i: integer;
begin
  Result := '';
  for i := FQFirst to FQLast do
    Result := Result + FTokenQueue[i].text;
end;

procedure TPascalTokeniser.SetTokenText(text: string);
begin
  FString := text;
end;

constructor TPascalTokeniser.Create;
begin
  inherited Create;
  Reset;
end;

destructor TPascalTokeniser.Destroy;
begin
  Reset;
  inherited Destroy;
end;

procedure TPascalTokeniser.Reset;
begin
  FNextToken := pstInit;
  FState := stDefault;
  FString := '';
  FEOF := false;
  FLastChar := #0;
  FLineNo := 0;
  FCharNo := 0;
  FDirective := '';
  FSkipNext := false;
  ResetQueue;
end;

function TPascalTokeniser.ReadCharacters(NumOfChars: integer): string;
var i: integer;
begin
  Result := FLastChar;
  for i := 2 to NumOfChars do
  begin
    if GetNext = pstEOF then Exit;
    Result := Result + FLastChar;
  end;
  GetNext;
end;

{Returns true if "w" is a Pascal reserved word, and the
 corresponding TPascalTokens value.}

function TPascalTokeniser.FindReservedWord(w : string;
  var token : TPascalTokens) : boolean;
var i: TPascalTokens;
begin
   Result := true;
   w := UpperCase(Trim(w));
   for i := Low(TPascalReservedWords) to High(TPascalReservedWords) do
   begin
       if w = pascalReservedWords[i] then
       begin
         token := i;
         if (token = pstEnd) and (FNextToken = pstPeriod) then
         begin
           token := pstEndOfUnit;
           GetNextToken;
         end;
         Exit;
       end;
   end;
   Result := false;
end;


function TPascalTokeniser.GetNextToken: TPascalTokens;
begin
  if FQueueState = tsRelease then
  repeat
    PopQueue(Result);
    FEOF := Result = pstEOF;
    if TokenFound(Result) then
      Exit;
  until FQueueState <> tsRelease;

  Result := InternalGetNextToken;
end;

{a simple lookahead one algorithm to extra the next symbol}

function TPascalTokeniser.InternalGetNextToken: TPascalTokens;
var C: char;
begin
  Result := pstEOF;

  FDirective := '';

  if FNextToken = pstInit then
    GetNext;

  repeat
    if FSkipNext then
    begin
      FSkipNext := false;
      GetNext;
    end;

    Result := FNextToken;
    C := FLastChar;
    GetNext;

    if (Result = pstCR) and (FNextToken = pstEOL) then
    begin
      FSkipNext := true;
      Result := pstEOL;
      C := LF;
      FCharNo := 0;
    end;

    case FState of
    stInComment:
      begin
        if Result = pstCloseBrace then
        begin
          FState := stDefault;
          Result := pstComment;
        end
        else
        if Result = pstEOL then
          FString := FString + LineEnding
        else
          FString := FString + C;
      end;

    stInComment2:
      begin
        if (Result = pstAsterisk) and (FNextToken = pstCloseBracket) then
        begin
          FState := stDefault;
          Result := pstComment2;
          GetNext;
        end
        else
        if Result = pstEOL then
          FString := FString + LineEnding
        else
          FString := FString + C;
      end;

    stInDirectiveType:
      begin
        FString := FString + C;
        Result := pstIdentifier;
        if not (FNextToken in [pstIdentifier,pstNumberstring]) then
        begin
          FDirective := FString;
          FString := '';
          FState := stInDirective
        end;
      end;

    stInDirective:
      begin
        if Result = pstCloseBrace then
        begin
          FState := stDefault;
          Result := pstDirective;
        end
        else
        if Result = pstEOL then
          FString := FString + LineEnding
        else
          FString := FString + C;
    end;

    stInCommentLine:
      begin
        case Result of
        pstEOL:
          begin
            FState := stDefault;
            Result := pstCommentLine;
          end;

        else
          FString := FString + C;
        end;
      end;

    stSingleQuoted:
      begin
        if (Result = pstSingleQuotes) then
        begin
          if (FNextToken = pstSingleQuotes) then
          begin
            FSkipNext := true;
            FString := FString + C;
          end
          else
          begin
            Result := pstQuotedstring;
            FState := stDefault;
          end;
        end
        else
        if Result = pstEOL then
        raise Exception.CreateFmt(rsstringliteralEOL,[LineNo,CharNo])
        else
          FString := FString + C;
      end;

    stDoubleQuoted:
      begin
        if (Result = pstDoubleQuotes) then
        begin
          if (FNextToken = pstDoubleQuotes) then
          begin
            FSkipNext := true;
            FString := FString + C;
          end
          else
          begin
            Result := pstDoubleQuotedstring;
            FState := stDefault;
          end;
        end
        else
        if Result = pstEOL then
          raise Exception.CreateFmt(rsDoublestringliteralEOL,[LineNo,CharNo])
        else
          FString := FString + C;
      end;

    stInIdentifier:
      begin
        FString := FString + C;
        Result := pstIdentifier;
        if not (FNextToken in [pstIdentifier,pstNumberstring]) then
          FState := stDefault
      end;

    stInNumeric:
      begin
        FString := FString + C;
        if (Result = pstPeriod) and (FNextToken = pstPeriod) then
        begin
          {malformed decimal}
          FState := stInIdentifier;
          Result := pstIdentifier
        end
        else
        begin
          if not (FNextToken in [pstNumberstring,pstPeriod]) then
            FState := stDefault;
          Result := pstNumberstring;
        end;
      end;

    else {stDefault}
      begin
        FString := C;
        case Result of

        pstOpenBracket:
          begin
            if FNextToken = pstAsterisk then
            begin
              FString := '';
              GetNext;
              FState := stInComment2;
            end
          end;

        pstForwardSlash:
          begin
            if FNextToken = pstForwardSlash then
            begin
              FString := '';
              GetNext;
              FState := stInCommentLine;
            end
          end;

        pstOpenBrace:
          begin
            FString := '';
            FState := stInComment;
            if FNextToken = pstDollar then
            begin
              GetNext;
              if FNextToken = pstIdentifier then
                FState := stInDirectiveType
            end
          end;

        pstMinus:
          begin
            if FNextToken = pstMinus then
            begin
              FString := '';
              GetNext;
              FState := stInCommentLine;
            end;
          end;

        pstSingleQuotes:
          begin
            FString := '';
            FState := stSingleQuoted;
          end;

        pstDoubleQuotes:
          begin
            FString := '';
            FState := stDoubleQuoted;
          end;

        pstIdentifier:
          if FNextToken in [pstIdentifier,pstNumberstring] then
            FState := stInIdentifier;

        pstNumberstring:
          if FNextToken in [pstNumberstring,pstPeriod] then
            FState := stInNumeric;

        pstEOL:
            FString := LineEnding;

        end;
      end;
    end;

//    writeln(FString);
    FEOF := Result = pstEOF;
  until TokenFound(Result) or EOF;
end;



end.

