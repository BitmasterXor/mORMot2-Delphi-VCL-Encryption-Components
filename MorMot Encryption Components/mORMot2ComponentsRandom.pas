unit mORMot2ComponentsRandom;

interface

uses
  System.Classes, System.SysUtils,
  mormot.core.base, mormot.core.text, mormot.core.buffers, mormot.crypt.core, mormot.crypt.secure;

type
  TRandomOutputFormat = (rofBinary, rofHexadecimal, rofBase64, rofBase64URL, rofUpperHex, rofLowerHex);
  TRandomDataType = (rdtBytes, rdtPassword, rdtKey, rdtSalt, rdtUUID, rdtToken);

  TmORMotRandom = class(TComponent)
  private
    FOutputFormat: TRandomOutputFormat;
    FDataType: TRandomDataType;
    FLength: Integer;
    FIncludeUppercase: Boolean;
    FIncludeLowercase: Boolean;
    FIncludeNumbers: Boolean;
    FIncludeSymbols: Boolean;
    FExcludeAmbiguous: Boolean;
    FCustomCharset: string;
    FOnRandomGenerated: TNotifyEvent;
    FOnError: TNotifyEvent;
    FLastError: string;
    FLastRandom: string;
    FPerformanceMs: Cardinal;
    FMinLength: Integer;
    FMaxLength: Integer;

    function GetDataTypeDescription: string;
    function GetRecommendedLength: Integer;
    procedure SetDataType(const Value: TRandomDataType);
    procedure SetDataLength(const Value: Integer);
    function EncodeOutput(const Data: RawByteString): string;
    function ValidateParameters: Boolean;
    function GetPasswordCharset: string;
  protected
    procedure DoRandomGenerated; virtual;
    procedure DoError(const ErrorMsg: string); virtual;
  public
    constructor Create(AOwner: TComponent); override;

    // Main random generation methods
    function GenerateRandom(Length: Integer = 0): string;
    function GenerateRandomData(Length: Integer = 0): RawByteString;
    function GeneratePassword(Length: Integer = 0): string;
    function GenerateKey(Length: Integer = 0): string;
    function GenerateSalt(Length: Integer = 0): string;
    function GenerateUUID: string;
    function GenerateToken(Length: Integer = 0): string;

    // Utility methods
    function GenerateRandomInteger(Min, Max: Integer): Integer;
    function GenerateRandomFloat: Double;
    function GenerateRandomBoolean: Boolean;
    function GenerateRandomChoice(const Choices: array of string): string;
    procedure FillRandomBuffer(Buffer: Pointer; Size: Integer);

    // Validation methods
    function TestRandomness(const Data: RawByteString): Double;
    function IsRandomnessGood(const Data: RawByteString): Boolean;

    // Properties (read-only)
    property LastError: string read FLastError;
    property LastRandom: string read FLastRandom;
    property PerformanceMs: Cardinal read FPerformanceMs;
    property DataTypeDescription: string read GetDataTypeDescription;
    property RecommendedLength: Integer read GetRecommendedLength;

  published
    property OutputFormat: TRandomOutputFormat read FOutputFormat write FOutputFormat default rofHexadecimal;
    property DataType: TRandomDataType read FDataType write SetDataType default rdtBytes;
    property Length: Integer read FLength write SetDataLength default 32;
    property IncludeUppercase: Boolean read FIncludeUppercase write FIncludeUppercase default True;
    property IncludeLowercase: Boolean read FIncludeLowercase write FIncludeLowercase default True;
    property IncludeNumbers: Boolean read FIncludeNumbers write FIncludeNumbers default True;
    property IncludeSymbols: Boolean read FIncludeSymbols write FIncludeSymbols default False;
    property ExcludeAmbiguous: Boolean read FExcludeAmbiguous write FExcludeAmbiguous default True;
    property CustomCharset: string read FCustomCharset write FCustomCharset;
    property MinLength: Integer read FMinLength write FMinLength default 1;
    property MaxLength: Integer read FMaxLength write FMaxLength default 1024;

    // Events
    property OnRandomGenerated: TNotifyEvent read FOnRandomGenerated write FOnRandomGenerated;
    property OnError: TNotifyEvent read FOnError write FOnError;
  end;

implementation

uses
  mormot.core.datetime;

{ TmORMotRandom }

constructor TmORMotRandom.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FOutputFormat := rofHexadecimal;
  FDataType := rdtBytes;
  FLength := 32;
  FIncludeUppercase := True;
  FIncludeLowercase := True;
  FIncludeNumbers := True;
  FIncludeSymbols := False;
  FExcludeAmbiguous := True;
  FCustomCharset := '';
  FMinLength := 1;
  FMaxLength := 1024;
  FLastError := '';
  FLastRandom := '';
end;

procedure TmORMotRandom.DoRandomGenerated;
begin
  if Assigned(FOnRandomGenerated) then
    FOnRandomGenerated(Self);
end;

procedure TmORMotRandom.DoError(const ErrorMsg: string);
begin
  FLastError := ErrorMsg;
  if Assigned(FOnError) then
    FOnError(Self);
end;

function TmORMotRandom.GetDataTypeDescription: string;
begin
  case FDataType of
    rdtBytes: Result := 'Raw random bytes';
    rdtPassword: Result := 'Random password with customizable character sets';
    rdtKey: Result := 'Cryptographic key material';
    rdtSalt: Result := 'Cryptographic salt for hashing/key derivation';
    rdtUUID: Result := 'Universally Unique Identifier (UUID4)';
    rdtToken: Result := 'Random token for authentication/session management';
  else
    Result := 'Unknown data type';
  end;
end;

function TmORMotRandom.GetRecommendedLength: Integer;
begin
  case FDataType of
    rdtBytes: Result := 32;
    rdtPassword: Result := 16;
    rdtKey: Result := 32;
    rdtSalt: Result := 16;
    rdtUUID: Result := 16;
    rdtToken: Result := 32;
  else
    Result := 32;
  end;
end;

procedure TmORMotRandom.SetDataType(const Value: TRandomDataType);
begin
  if FDataType <> Value then
  begin
    FDataType := Value;
    FLength := GetRecommendedLength;
    FLastRandom := '';
    FLastError := '';
  end;
end;

procedure TmORMotRandom.SetDataLength(const Value: Integer);
begin
  if Value < FMinLength then
    FLength := FMinLength
  else if Value > FMaxLength then
    FLength := FMaxLength
  else
    FLength := Value;

  FLastRandom := '';
  FLastError := '';
end;

function TmORMotRandom.EncodeOutput(const Data: RawByteString): string;
begin
  try
    case FOutputFormat of
      rofBinary: Result := UTF8ToString(Data);
      rofHexadecimal: Result := LowerCase(BinToHex(Data));
      rofBase64: Result := BinToBase64(Data);
      rofBase64URL: Result := BinToBase64uri(Data);
      rofUpperHex: Result := UpperCase(BinToHex(Data));
      rofLowerHex: Result := LowerCase(BinToHex(Data));
    else
      Result := LowerCase(BinToHex(Data));
    end;
  except
    on E: Exception do
    begin
      DoError('Output encoding failed: ' + E.Message);
      Result := '';
    end;
  end;
end;

function TmORMotRandom.ValidateParameters: Boolean;
begin
  Result := False;

  if FLength < FMinLength then
  begin
    DoError(Format('Length must be at least %d', [FMinLength]));
    Exit;
  end;

  if FLength > FMaxLength then
  begin
    DoError(Format('Length cannot exceed %d', [FMaxLength]));
    Exit;
  end;

  if (FDataType = rdtPassword) and (FCustomCharset = '') then
  begin
    if not (FIncludeUppercase or FIncludeLowercase or FIncludeNumbers or FIncludeSymbols) then
    begin
      DoError('At least one character set must be enabled for password generation');
      Exit;
    end;
  end;

  Result := True;
end;

function TmORMotRandom.GetPasswordCharset: string;
const
  UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
  NUMBERS = '0123456789';
  SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  AMBIGUOUS = '0O1lI|`~';
var
  Charset: string;
  i: Integer;
begin
  if FCustomCharset <> '' then
  begin
    Result := FCustomCharset;
    Exit;
  end;

  Charset := '';

  if FIncludeUppercase then
    Charset := Charset + UPPERCASE;

  if FIncludeLowercase then
    Charset := Charset + LOWERCASE;

  if FIncludeNumbers then
    Charset := Charset + NUMBERS;

  if FIncludeSymbols then
    Charset := Charset + SYMBOLS;

  if FExcludeAmbiguous then
  begin
    for i := 1 to System.Length(AMBIGUOUS) do
    begin
      Charset := StringReplace(Charset, AMBIGUOUS[i], '', [rfReplaceAll]);
    end;
  end;

  Result := Charset;
end;

function TmORMotRandom.GenerateRandom(Length: Integer): string;
var
  StartTime: TDateTime;
  LengthToUse: Integer;
  RandomData: RawByteString;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if Length > 0 then
      LengthToUse := Length
    else
      LengthToUse := FLength;

    FLength := LengthToUse;

    if not ValidateParameters then
      Exit;

    case FDataType of
      rdtBytes, rdtKey, rdtSalt:
        begin
          // Use exact same syntax as your working demo
          RandomData := TAesPrng.Fill(LengthToUse);
          Result := EncodeOutput(RandomData);
        end;

      rdtPassword:
        Result := GeneratePassword(LengthToUse);

      rdtUUID:
        Result := GenerateUUID;

      rdtToken:
        begin
          RandomData := TAesPrng.Fill(LengthToUse);
          Result := BinToBase64uri(RandomData);
        end;
    end;

    FLastRandom := Result;
    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoRandomGenerated;

  except
    on E: Exception do
      DoError('Random generation failed: ' + E.Message);
  end;
end;

function TmORMotRandom.GenerateRandomData(Length: Integer): RawByteString;
var
  LengthToUse: Integer;
begin
  Result := '';
  FLastError := '';

  try
    if Length > 0 then
      LengthToUse := Length
    else
      LengthToUse := FLength;

    if (LengthToUse < FMinLength) or (LengthToUse > FMaxLength) then
    begin
      DoError('Invalid length specified');
      Exit;
    end;

    // Use exact same syntax as your working demo
    Result := TAesPrng.Fill(LengthToUse);

  except
    on E: Exception do
      DoError('Random data generation failed: ' + E.Message);
  end;
end;

function TmORMotRandom.GeneratePassword(Length: Integer): string;
var
  StartTime: TDateTime;
  LengthToUse: Integer;
  Charset: string;
  i: Integer;
  RandomBytes: RawByteString;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if Length > 0 then
      LengthToUse := Length
    else
      LengthToUse := FLength;

    Charset := GetPasswordCharset;
    if Charset = '' then
    begin
      DoError('No character set available for password generation');
      Exit;
    end;

    // Use exact same syntax as your working demo
    RandomBytes := TAesPrng.Fill(LengthToUse);
    SetLength(Result, LengthToUse);

    for i := 1 to LengthToUse do
    begin
      Result[i] := Charset[(Ord(RandomBytes[i]) mod System.Length(Charset)) + 1];
    end;

    FLastRandom := Result;
    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoRandomGenerated;

  except
    on E: Exception do
      DoError('Password generation failed: ' + E.Message);
  end;
end;

function TmORMotRandom.GenerateKey(Length: Integer): string;
var
  LengthToUse: Integer;
  KeyData: RawByteString;
begin
  if Length > 0 then
    LengthToUse := Length
  else
    LengthToUse := FLength;

  // Use exact same syntax as your working demo
  KeyData := TAesPrng.Fill(LengthToUse);
  Result := BinToHex(KeyData);
end;

function TmORMotRandom.GenerateSalt(Length: Integer): string;
var
  LengthToUse: Integer;
  SaltData: RawByteString;
begin
  if Length > 0 then
    LengthToUse := Length
  else
    LengthToUse := FLength;

  if LengthToUse < 8 then
    LengthToUse := 16;

  // Use exact same syntax as your working demo
  SaltData := TAesPrng.Fill(LengthToUse);
  Result := BinToHex(SaltData);
end;

function TmORMotRandom.GenerateUUID: string;
var
  UUIDBytes: RawByteString;
  UUIDRec: packed record
    TimeLow: Cardinal;
    TimeMid: Word;
    TimeHiAndVersion: Word;
    ClockSeqHiAndReserved: Byte;
    ClockSeqLow: Byte;
    Node: array[0..5] of Byte;
  end;
begin
  try
    // Use exact same syntax as your working demo
    UUIDBytes := TAesPrng.Fill(16);

    Move(UUIDBytes[1], UUIDRec, 16);

    // Set version 4 (random UUID) and variant bits
    UUIDRec.TimeHiAndVersion := (UUIDRec.TimeHiAndVersion and $0FFF) or $4000;
    UUIDRec.ClockSeqHiAndReserved := (UUIDRec.ClockSeqHiAndReserved and $3F) or $80;

    Result := Format('%.8x-%.4x-%.4x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x',
      [UUIDRec.TimeLow, UUIDRec.TimeMid, UUIDRec.TimeHiAndVersion,
       UUIDRec.ClockSeqHiAndReserved, UUIDRec.ClockSeqLow,
       UUIDRec.Node[0], UUIDRec.Node[1], UUIDRec.Node[2],
       UUIDRec.Node[3], UUIDRec.Node[4], UUIDRec.Node[5]]);

  except
    on E: Exception do
    begin
      DoError('UUID generation failed: ' + E.Message);
      Result := '';
    end;
  end;
end;

function TmORMotRandom.GenerateToken(Length: Integer): string;
var
  LengthToUse: Integer;
  TokenData: RawByteString;
begin
  if Length > 0 then
    LengthToUse := Length
  else
    LengthToUse := FLength;

  // Use exact same syntax as your working demo
  TokenData := TAesPrng.Fill(LengthToUse);
  Result := BinToBase64uri(TokenData);
end;

function TmORMotRandom.GenerateRandomInteger(Min, Max: Integer): Integer;
var
  Range: Cardinal;
  RandomBytes: RawByteString;
  RandomValue: Cardinal;
begin
  if Min >= Max then
  begin
    DoError('Min must be less than Max');
    Result := Min;
    Exit;
  end;

  Range := Cardinal(Max - Min);
  // Use exact same syntax as your working demo
  RandomBytes := TAesPrng.Fill(4);
  Move(RandomBytes[1], RandomValue, 4);
  Result := Min + Integer(RandomValue mod (Range + 1));
end;

function TmORMotRandom.GenerateRandomFloat: Double;
var
  RandomBytes: RawByteString;
  RandomValue: Cardinal;
begin
  // Use exact same syntax as your working demo
  RandomBytes := TAesPrng.Fill(4);
  Move(RandomBytes[1], RandomValue, 4);
  Result := RandomValue / High(Cardinal);
end;

function TmORMotRandom.GenerateRandomBoolean: Boolean;
var
  RandomBytes: RawByteString;
begin
  // Use exact same syntax as your working demo
  RandomBytes := TAesPrng.Fill(1);
  Result := (Ord(RandomBytes[1]) and 1) = 1;
end;

function TmORMotRandom.GenerateRandomChoice(const Choices: array of string): string;
var
  Index: Integer;
  ChoiceCount: Integer;
begin
  ChoiceCount := System.Length(Choices);
  if ChoiceCount = 0 then
  begin
    DoError('Choices array cannot be empty');
    Result := '';
    Exit;
  end;

  Index := GenerateRandomInteger(0, ChoiceCount - 1);
  Result := Choices[Index];
end;

procedure TmORMotRandom.FillRandomBuffer(Buffer: Pointer; Size: Integer);
var
  RandomData: RawByteString;
begin
  try
    if not Assigned(Buffer) then
    begin
      DoError('Buffer cannot be nil');
      Exit;
    end;

    if Size <= 0 then
    begin
      DoError('Size must be positive');
      Exit;
    end;

    // Use exact same syntax as your working demo
    RandomData := TAesPrng.Fill(Size);
    Move(RandomData[1], Buffer^, Size);

  except
    on E: Exception do
      DoError('Buffer fill failed: ' + E.Message);
  end;
end;

function TmORMotRandom.TestRandomness(const Data: RawByteString): Double;
var
  ByteCounts: array[0..255] of Integer;
  i: Integer;
  Entropy: Double;
  Probability: Double;
  DataLength: Integer;
begin
  Result := 0.0;

  try
    DataLength := System.Length(Data);
    if DataLength = 0 then
      Exit;

    FillChar(ByteCounts, SizeOf(ByteCounts), 0);

    for i := 1 to DataLength do
      Inc(ByteCounts[Ord(Data[i])]);

    Entropy := 0.0;
    for i := 0 to 255 do
    begin
      if ByteCounts[i] > 0 then
      begin
        Probability := ByteCounts[i] / DataLength;
        Entropy := Entropy - (Probability * (Ln(Probability) / Ln(2)));
      end;
    end;

    Result := Entropy;

  except
    on E: Exception do
      DoError('Randomness test failed: ' + E.Message);
  end;
end;

function TmORMotRandom.IsRandomnessGood(const Data: RawByteString): Boolean;
var
  Entropy: Double;
begin
  Entropy := TestRandomness(Data);
  // Entropy close to 8.0 is ideal for random data
  Result := Entropy >= 7.5;
end;

end.
