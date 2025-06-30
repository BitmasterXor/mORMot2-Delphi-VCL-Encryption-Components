unit mORMot2ComponentsPBKDF2;

interface

uses
  System.Classes, System.SysUtils,
  mormot.core.base, mormot.core.text, mormot.core.buffers, mormot.crypt.core, mormot.crypt.secure;

type
  TPBKDF2Algorithm = (pbkdfSHA1, pbkdfSHA256, pbkdfSHA384, pbkdfSHA512);
  TOutputEncoding = (oeBase64, oeHexadecimal, oeLowerHex, oeUpperHex, oeRaw);

  TmORMotPBKDF2 = class(TComponent)
  private
    FPBKDF2Algorithm: TPBKDF2Algorithm;
    FOutputEncoding: TOutputEncoding;
    FPassword: string;
    FSalt: string;
    FIterations: Integer;
    FKeyLength: Integer;
    FOnKeyDerivationComplete: TNotifyEvent;
    FOnError: TNotifyEvent;
    FLastError: string;
    FLastDerivedKey: string;
    FPerformanceMs: Cardinal;
    FAutoGenerateSalt: Boolean;
    FMinIterations: Integer;

    function GetPBKDF2AlgorithmText: string;
    function GetRecommendedIterations: Integer;
    function GetSecurityLevel: string;
    procedure SetPBKDF2Algorithm(const Value: TPBKDF2Algorithm);
    procedure SetIterations(const Value: Integer);
    function EncodeOutput(const Data: RawByteString): string;
    function ValidateParameters: Boolean;
  protected
    procedure DoKeyDerivationComplete; virtual;
    procedure DoError(const ErrorMsg: string); virtual;
  public
    constructor Create(AOwner: TComponent); override;

    function DeriveKey(const Password: string = ''; const Salt: string = '';
                      Iterations: Integer = 0; KeyLength: Integer = 0): string;
    function DeriveKeyData(const Password, Salt: RawByteString;
                          Iterations, KeyLength: Integer): RawByteString;
    function DeriveKeyFromComponents: string;

    function VerifyPassword(const Password, Salt, ExpectedKey: string;
                           Iterations, KeyLength: Integer): Boolean;

    function GenerateRandomSalt(SaltLength: Integer = 16): string;
    function EstimateDerivationTime(Iterations: Integer): Cardinal;
    function CompareKeys(const Key1, Key2: string): Boolean;
    procedure ClearSensitiveData;
    procedure ClearResults;

    property LastError: string read FLastError;
    property LastDerivedKey: string read FLastDerivedKey;
    property PerformanceMs: Cardinal read FPerformanceMs;
    property PBKDF2AlgorithmText: string read GetPBKDF2AlgorithmText;
    property RecommendedIterations: Integer read GetRecommendedIterations;
    property SecurityLevel: string read GetSecurityLevel;

  published
    property PBKDF2Algorithm: TPBKDF2Algorithm read FPBKDF2Algorithm write SetPBKDF2Algorithm default pbkdfSHA256;
    property OutputEncoding: TOutputEncoding read FOutputEncoding write FOutputEncoding default oeHexadecimal;
    property Password: string read FPassword write FPassword;
    property Salt: string read FSalt write FSalt;
    property Iterations: Integer read FIterations write SetIterations default 100000;
    property KeyLength: Integer read FKeyLength write FKeyLength default 32;
    property AutoGenerateSalt: Boolean read FAutoGenerateSalt write FAutoGenerateSalt default True;
    property MinIterations: Integer read FMinIterations write FMinIterations default 10000;

    property OnKeyDerivationComplete: TNotifyEvent read FOnKeyDerivationComplete write FOnKeyDerivationComplete;
    property OnError: TNotifyEvent read FOnError write FOnError;
  end;

implementation

uses
  mormot.core.datetime;

{ TmORMotPBKDF2 }

constructor TmORMotPBKDF2.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FPBKDF2Algorithm := pbkdfSHA256;
  FOutputEncoding := oeHexadecimal;
  FPassword := '';
  FSalt := '';
  FIterations := 100000;
  FKeyLength := 32;
  FAutoGenerateSalt := True;
  FMinIterations := 10000;
  FLastError := '';
  FLastDerivedKey := '';
end;

procedure TmORMotPBKDF2.DoKeyDerivationComplete;
begin
  if Assigned(FOnKeyDerivationComplete) then
    FOnKeyDerivationComplete(Self);
end;

procedure TmORMotPBKDF2.DoError(const ErrorMsg: string);
begin
  FLastError := ErrorMsg;
  if Assigned(FOnError) then
    FOnError(Self);
end;

function TmORMotPBKDF2.GetPBKDF2AlgorithmText: string;
begin
  case FPBKDF2Algorithm of
    pbkdfSHA1: Result := 'PBKDF2-HMAC-SHA1';
    pbkdfSHA256: Result := 'PBKDF2-HMAC-SHA256';
    pbkdfSHA384: Result := 'PBKDF2-HMAC-SHA384';
    pbkdfSHA512: Result := 'PBKDF2-HMAC-SHA512';
  else
    Result := 'Unknown';
  end;
end;

function TmORMotPBKDF2.GetRecommendedIterations: Integer;
begin
  case FPBKDF2Algorithm of
    pbkdfSHA1: Result := 100000;
    pbkdfSHA256: Result := 100000;
    pbkdfSHA384: Result := 100000;
    pbkdfSHA512: Result := 100000;
  else
    Result := 100000;
  end;
end;

function TmORMotPBKDF2.GetSecurityLevel: string;
begin
  if FIterations < FMinIterations then
    Result := 'WEAK (Iterations too low)'
  else
  begin
    case FPBKDF2Algorithm of
      pbkdfSHA1:
        if FIterations >= 100000 then
          Result := 'ACCEPTABLE (SHA1 deprecated)'
        else
          Result := 'WEAK';
      pbkdfSHA256:
        if FIterations >= 100000 then
          Result := 'STRONG'
        else
          Result := 'MODERATE';
      pbkdfSHA384, pbkdfSHA512:
        if FIterations >= 100000 then
          Result := 'VERY STRONG'
        else
          Result := 'STRONG';
    else
      Result := 'UNKNOWN';
    end;
  end;
end;

procedure TmORMotPBKDF2.SetPBKDF2Algorithm(const Value: TPBKDF2Algorithm);
begin
  if FPBKDF2Algorithm <> Value then
  begin
    FPBKDF2Algorithm := Value;
    FLastDerivedKey := '';
    FLastError := '';
  end;
end;

procedure TmORMotPBKDF2.SetIterations(const Value: Integer);
begin
  if Value < 1 then
    FIterations := 1
  else
    FIterations := Value;

  FLastDerivedKey := '';
  FLastError := '';
end;

function TmORMotPBKDF2.EncodeOutput(const Data: RawByteString): string;
begin
  try
    case FOutputEncoding of
      oeBase64: Result := BinToBase64(Data);
      oeHexadecimal: Result := LowerCase(BinToHex(Data));
      oeLowerHex: Result := LowerCase(BinToHex(Data));
      oeUpperHex: Result := UpperCase(BinToHex(Data));
      oeRaw: Result := UTF8ToString(Data);
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

function TmORMotPBKDF2.ValidateParameters: Boolean;
begin
  Result := False;

  if FIterations < 1 then
  begin
    DoError('Iterations must be at least 1');
    Exit;
  end;

  if FIterations < FMinIterations then
  begin
    DoError(Format('Iterations should be at least %d for security', [FMinIterations]));
    Exit;
  end;

  if FKeyLength < 1 then
  begin
    DoError('Key length must be at least 1 byte');
    Exit;
  end;

  if FKeyLength > 1024 then
  begin
    DoError('Key length cannot exceed 1024 bytes');
    Exit;
  end;

  Result := True;
end;

function TmORMotPBKDF2.DeriveKey(const Password, Salt: string;
                                Iterations, KeyLength: Integer): string;
var
  StartTime: TDateTime;
  PasswordToUse, SaltToUse: string;
  IterationsToUse, KeyLengthToUse: Integer;
  PasswordBytes, SaltBytes: RawByteString;
  DerivedKey: THash256;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if Password <> '' then
      PasswordToUse := Password
    else
      PasswordToUse := FPassword;

    if Salt <> '' then
      SaltToUse := Salt
    else
    begin
      if FAutoGenerateSalt and (FSalt = '') then
        SaltToUse := GenerateRandomSalt
      else
        SaltToUse := FSalt;
    end;

    if Iterations > 0 then
      IterationsToUse := Iterations
    else
      IterationsToUse := FIterations;

    if KeyLength > 0 then
      KeyLengthToUse := KeyLength
    else
      KeyLengthToUse := FKeyLength;

    if PasswordToUse = '' then
    begin
      DoError('Password cannot be empty');
      Exit;
    end;

    if SaltToUse = '' then
    begin
      DoError('Salt cannot be empty');
      Exit;
    end;

    // Temporarily set properties for validation
    FIterations := IterationsToUse;
    FKeyLength := KeyLengthToUse;

    if not ValidateParameters then
      Exit;

    PasswordBytes := ToUtf8(PasswordToUse);
    SaltBytes := ToUtf8(SaltToUse);

    // Use exactly like your working demo code
    case FPBKDF2Algorithm of
      pbkdfSHA256:
        begin
          // Use exact same syntax as your working demo
          Pbkdf2HmacSha256(PasswordBytes, SaltBytes, IterationsToUse, DerivedKey);
          Result := BinToHex(@DerivedKey, SizeOf(DerivedKey));
        end;
      pbkdfSHA1:
        begin
          DoError('PBKDF2-SHA1 not available in this mORMot version');
          Exit;
        end;
      pbkdfSHA384:
        begin
          DoError('PBKDF2-SHA384 not available in this mORMot version');
          Exit;
        end;
      pbkdfSHA512:
        begin
          DoError('PBKDF2-SHA512 not available in this mORMot version');
          Exit;
        end;
    else
      begin
        DoError('Unsupported PBKDF2 algorithm');
        Exit;
      end;
    end;

    if FAutoGenerateSalt and (FSalt = '') then
      FSalt := SaltToUse;

    if FOutputEncoding <> oeHexadecimal then
      Result := EncodeOutput(HexToBin(Result));

    FLastDerivedKey := Result;

    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoKeyDerivationComplete;

    // Security: Clear sensitive key data from memory
    FillChar(DerivedKey, SizeOf(DerivedKey), 0);

  except
    on E: Exception do
      DoError('Key derivation failed: ' + E.Message);
  end;
end;

function TmORMotPBKDF2.DeriveKeyData(const Password, Salt: RawByteString;
                                    Iterations, KeyLength: Integer): RawByteString;
var
  StartTime: TDateTime;
  DerivedKey: THash256;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if Length(Password) = 0 then
    begin
      DoError('Password cannot be empty');
      Exit;
    end;

    if Length(Salt) = 0 then
    begin
      DoError('Salt cannot be empty');
      Exit;
    end;

    if Iterations < 1 then
    begin
      DoError('Iterations must be at least 1');
      Exit;
    end;

    if KeyLength <> 32 then
    begin
      DoError('Only 32-byte keys supported in this version');
      Exit;
    end;

    case FPBKDF2Algorithm of
      pbkdfSHA256:
        begin
          Pbkdf2HmacSha256(Password, Salt, Iterations, DerivedKey);
          SetLength(Result, SizeOf(DerivedKey));
          Move(DerivedKey, Result[1], SizeOf(DerivedKey));
        end;
    else
      begin
        DoError('Only PBKDF2-SHA256 supported in this version');
        Exit;
      end;
    end;

    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoKeyDerivationComplete;

    // Security: Clear sensitive key data from memory
    FillChar(DerivedKey, SizeOf(DerivedKey), 0);

  except
    on E: Exception do
      DoError('Key derivation failed: ' + E.Message);
  end;
end;

function TmORMotPBKDF2.DeriveKeyFromComponents: string;
begin
  Result := DeriveKey(FPassword, FSalt, FIterations, FKeyLength);
end;

function TmORMotPBKDF2.VerifyPassword(const Password, Salt, ExpectedKey: string;
                                     Iterations, KeyLength: Integer): Boolean;
var
  ComputedKey: string;
begin
  Result := False;

  try
    ComputedKey := DeriveKey(Password, Salt, Iterations, KeyLength);
    if ComputedKey <> '' then
      Result := CompareKeys(ComputedKey, ExpectedKey);
  except
    on E: Exception do
      DoError('Password verification failed: ' + E.Message);
  end;
end;

function TmORMotPBKDF2.GenerateRandomSalt(SaltLength: Integer): string;
var
  SaltBytes: RawByteString;
begin
  try
    if SaltLength < 8 then
      SaltLength := 16;

    if SaltLength > 64 then
      SaltLength := 64;

    SaltBytes := TAesPrng.Fill(SaltLength);
    Result := BinToHex(SaltBytes);
  except
    on E: Exception do
    begin
      DoError('Random salt generation failed: ' + E.Message);
      Result := '';
    end;
  end;
end;

function TmORMotPBKDF2.EstimateDerivationTime(Iterations: Integer): Cardinal;
var
  TestStart: TDateTime;
  TestPassword, TestSalt: RawByteString;
  TestIterations: Integer;
  TestKey: THash256;
  ElapsedMs: Double;
begin
  Result := 0;

  try
    TestIterations := 1000;
    TestPassword := 'test';
    TestSalt := 'testsalt';

    TestStart := Now;

    case FPBKDF2Algorithm of
      pbkdfSHA256: Pbkdf2HmacSha256(TestPassword, TestSalt, TestIterations, TestKey);
    else
      begin
        DoError('Time estimation only available for PBKDF2-SHA256');
        Exit;
      end;
    end;

    ElapsedMs := (Now - TestStart) * 24 * 60 * 60 * 1000;
    Result := Trunc((ElapsedMs * Iterations) / TestIterations);

    // Security: Clear test key data
    FillChar(TestKey, SizeOf(TestKey), 0);

  except
    on E: Exception do
      DoError('Time estimation failed: ' + E.Message);
  end;
end;

function TmORMotPBKDF2.CompareKeys(const Key1, Key2: string): Boolean;
begin
  Result := SameText(Key1, Key2);
end;

procedure TmORMotPBKDF2.ClearSensitiveData;
begin
  FPassword := '';
  FSalt := '';
  FLastDerivedKey := '';
  FLastError := '';
end;

procedure TmORMotPBKDF2.ClearResults;
begin
  FLastDerivedKey := '';
  FLastError := '';
  FPerformanceMs := 0;
end;

end.
