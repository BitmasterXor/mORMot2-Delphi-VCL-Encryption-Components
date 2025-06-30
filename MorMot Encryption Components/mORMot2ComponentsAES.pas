unit mORMot2ComponentsAES;

interface

uses
  System.Classes, System.SysUtils, System.Types,
  mormot.core.base, mormot.core.text, mormot.crypt.core, mormot.crypt.secure,mormot.core.buffers;

type
  TAESMode = (amECB, amCBC, amCFB, amOFB, amCTR, amGCM, amCFC, amOFC, amCTC);
  TAESKeySize = (aks128, aks192, aks256);
  TOutputEncoding = (oeBase64, oeHexadecimal);

  TmORMotAES = class(TComponent)
  private
    FAESMode: TAESMode;
    FAESKeySize: TAESKeySize;
    FPassword: string;
    FOutputEncoding: TOutputEncoding;
    FUseRandomIV: Boolean;
    FSalt: string;
    FPBKDF2Iterations: Integer;
    FOnEncryptionComplete: TNotifyEvent;
    FOnDecryptionComplete: TNotifyEvent;
    FOnError: TNotifyEvent;
    FLastError: string;
    FLastResult: string;
    FPerformanceMs: Cardinal;

    function GetAESModeText: string;
    function GetKeySize: Integer;
    procedure SetAESMode(const Value: TAESMode);
    procedure SetAESKeySize(const Value: TAESKeySize);
    function DeriveKeyFromPassword(const Password, Salt: string): THash256;
    function EncodeOutput(const Data: RawByteString): string;
    function DecodeInput(const Data: string): RawByteString;
    function CreateAESInstance: TAesAbstract;
  protected
    procedure DoEncryptionComplete; virtual;
    procedure DoDecryptionComplete; virtual;
    procedure DoError(const ErrorMsg: string); virtual;
  public
    constructor Create(AOwner: TComponent); override;

    // Main encryption/decryption methods
    function EncryptText(const PlainText: string): string;
    function DecryptText(const CipherText: string): string;
    function EncryptData(const Data: RawByteString): RawByteString;
    function DecryptData(const Data: RawByteString): RawByteString;

    // Utility methods
    function GenerateRandomSalt: string;
    function ValidateSettings: Boolean;
    procedure ClearSensitiveData;

    // Properties (read-only)
    property LastError: string read FLastError;
    property LastResult: string read FLastResult;
    property PerformanceMs: Cardinal read FPerformanceMs;
    property AESModeText: string read GetAESModeText;
    property KeySizeBits: Integer read GetKeySize;

  published
    property AESMode: TAESMode read FAESMode write SetAESMode default amCBC;
    property AESKeySize: TAESKeySize read FAESKeySize write SetAESKeySize default aks256;
    property Password: string read FPassword write FPassword;
    property OutputEncoding: TOutputEncoding read FOutputEncoding write FOutputEncoding default oeBase64;
    property UseRandomIV: Boolean read FUseRandomIV write FUseRandomIV default True;
    property Salt: string read FSalt write FSalt;
    property PBKDF2Iterations: Integer read FPBKDF2Iterations write FPBKDF2Iterations default 10000;

    // Events
    property OnEncryptionComplete: TNotifyEvent read FOnEncryptionComplete write FOnEncryptionComplete;
    property OnDecryptionComplete: TNotifyEvent read FOnDecryptionComplete write FOnDecryptionComplete;
    property OnError: TNotifyEvent read FOnError write FOnError;
  end;

implementation

uses
  mormot.core.datetime;

{ TmORMotAES }

constructor TmORMotAES.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FAESMode := amCBC;
  FAESKeySize := aks256;
  FOutputEncoding := oeBase64;
  FUseRandomIV := True;
  FPBKDF2Iterations := 10000;
  FSalt := 'mormot_demo_fixed_salt_2024';
  FPassword := '';
  FLastError := '';
  FLastResult := '';
end;

procedure TmORMotAES.DoEncryptionComplete;
begin
  if Assigned(FOnEncryptionComplete) then
    FOnEncryptionComplete(Self);
end;

procedure TmORMotAES.DoDecryptionComplete;
begin
  if Assigned(FOnDecryptionComplete) then
    FOnDecryptionComplete(Self);
end;

procedure TmORMotAES.DoError(const ErrorMsg: string);
begin
  FLastError := ErrorMsg;
  if Assigned(FOnError) then
    FOnError(Self);
end;

function TmORMotAES.GetAESModeText: string;
begin
  case FAESMode of
    amECB: Result := 'AES-ECB';
    amCBC: Result := 'AES-CBC';
    amCFB: Result := 'AES-CFB';
    amOFB: Result := 'AES-OFB';
    amCTR: Result := 'AES-CTR';
    amGCM: Result := 'AES-GCM';
    amCFC: Result := 'AES-CFC';
    amOFC: Result := 'AES-OFC';
    amCTC: Result := 'AES-CTC';
  else
    Result := 'Unknown';
  end;
end;

function TmORMotAES.GetKeySize: Integer;
begin
  case FAESKeySize of
    aks128: Result := 128;
    aks192: Result := 192;
    aks256: Result := 256;
  else
    Result := 256;
  end;
end;

procedure TmORMotAES.SetAESMode(const Value: TAESMode);
begin
  if FAESMode <> Value then
  begin
    FAESMode := Value;
    FLastResult := '';
    FLastError := '';
  end;
end;

procedure TmORMotAES.SetAESKeySize(const Value: TAESKeySize);
begin
  if FAESKeySize <> Value then
  begin
    FAESKeySize := Value;
    FLastResult := '';
    FLastError := '';
  end;
end;

function TmORMotAES.DeriveKeyFromPassword(const Password, Salt: string): THash256;
var
  SaltBytes: RawByteString;
begin
  try
    if Salt = '' then
      SaltBytes := 'defaultsalt12345'
    else
      SaltBytes := ToUtf8(Salt);

    // Use PBKDF2HmacSha256 exactly like in your working code
    Pbkdf2HmacSha256(ToUtf8(Password), SaltBytes, FPBKDF2Iterations, Result);
  except
    on E: Exception do
    begin
      DoError('Key derivation failed: ' + E.Message);
      FillChar(Result, SizeOf(Result), 0);
    end;
  end;
end;

function TmORMotAES.EncodeOutput(const Data: RawByteString): string;
begin
  try
    case FOutputEncoding of
      oeBase64: Result := BinToBase64(Data);  // Like your working code
      oeHexadecimal: Result := BinToHex(Data);
    else
      Result := BinToBase64(Data);  // Like your working code
    end;
  except
    on E: Exception do
    begin
      DoError('Output encoding failed: ' + E.Message);
      Result := '';
    end;
  end;
end;

function TmORMotAES.DecodeInput(const Data: string): RawByteString;
begin
  try
    case FOutputEncoding of
      oeBase64: Result := Base64ToBin(Data);  // Like your working code
      oeHexadecimal: Result := HexToBin(Data);
    else
      Result := Base64ToBin(Data);  // Like your working code
    end;
  except
    on E: Exception do
    begin
      DoError('Input decoding failed: ' + E.Message);
      Result := '';
    end;
  end;
end;

function TmORMotAES.CreateAESInstance: TAesAbstract;
var
  Key: THash256;
  KeyBits: Integer;
begin
  Result := nil;
  KeyBits := GetKeySize;

  // Derive the key exactly like your working code
  Key := DeriveKeyFromPassword(FPassword, FSalt);

  // Create AES instances exactly like your working code
  try
    case FAESMode of
      amECB: Result := TAesEcb.Create(Key, KeyBits);
      amCBC: Result := TAesCbc.Create(Key, KeyBits);
      amCFB: Result := TAesCfb.Create(Key, KeyBits);
      amOFB: Result := TAesOfb.Create(Key, KeyBits);
      amCTR: Result := TAesCtr.Create(Key, KeyBits);
      amGCM: Result := TAesGcm.Create(Key, KeyBits);
      amCFC: Result := TAesCfc.Create(Key, KeyBits);
      amOFC: Result := TAesOfc.Create(Key, KeyBits);
      amCTC: Result := TAesCtc.Create(Key, KeyBits);
    end;
  finally
    // Clear key from memory
    FillChar(Key, SizeOf(Key), 0);
  end;
end;

function TmORMotAES.EncryptText(const PlainText: string): string;
var
  StartTime: TDateTime;  // Use TDateTime instead of Int64
  PlainData, CipherData: RawByteString;
  AES: TAesAbstract;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    if not ValidateSettings then
      Exit;

    StartTime := Now;  // Use Now instead of GetTickCount64

    // Convert to UTF-8 exactly like your working code
    PlainData := ToUtf8(PlainText);

    // Create AES instance
    AES := CreateAESInstance;
    if AES = nil then
    begin
      DoError('Failed to create AES instance');
      Exit;
    end;

    try
      // Encrypt with PKCS7 padding exactly like your working code
      CipherData := AES.EncryptPkcs7(PlainData, FUseRandomIV);

      // Encode output
      Result := EncodeOutput(CipherData);
      FLastResult := Result;

      // Calculate elapsed time like your working code
      ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
      FPerformanceMs := Trunc(ElapsedMs);
      DoEncryptionComplete;

    finally
      AES.Free;
    end;

  except
    on E: Exception do
      DoError('Encryption failed: ' + E.Message);
  end;
end;

function TmORMotAES.DecryptText(const CipherText: string): string;
var
  StartTime: TDateTime;  // Use TDateTime instead of Int64
  CipherData, PlainData: RawByteString;
  AES: TAesAbstract;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    if not ValidateSettings then
      Exit;

    StartTime := Now;  // Use Now instead of GetTickCount64

    // Decode input
    CipherData := DecodeInput(CipherText);
    if CipherData = '' then
      Exit;

    // Create AES instance
    AES := CreateAESInstance;
    if AES = nil then
    begin
      DoError('Failed to create AES instance');
      Exit;
    end;

    try
      // Decrypt with PKCS7 padding exactly like your working code
      PlainData := AES.DecryptPkcs7(CipherData, FUseRandomIV);

      // Convert back to string exactly like your working code
      Result := Utf8ToString(PlainData);
      FLastResult := Result;

      // Calculate elapsed time like your working code
      ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
      FPerformanceMs := Trunc(ElapsedMs);
      DoDecryptionComplete;

    finally
      AES.Free;
    end;

  except
    on E: Exception do
      DoError('Decryption failed: ' + E.Message);
  end;
end;

function TmORMotAES.EncryptData(const Data: RawByteString): RawByteString;
var
  AES: TAesAbstract;
begin
  Result := '';
  FLastError := '';

  try
    if not ValidateSettings then
      Exit;

    AES := CreateAESInstance;
    if AES = nil then
    begin
      DoError('Failed to create AES instance');
      Exit;
    end;

    try
      Result := AES.EncryptPkcs7(Data, FUseRandomIV);
    finally
      AES.Free;
    end;

  except
    on E: Exception do
      DoError('Data encryption failed: ' + E.Message);
  end;
end;

function TmORMotAES.DecryptData(const Data: RawByteString): RawByteString;
var
  AES: TAesAbstract;
begin
  Result := '';
  FLastError := '';

  try
    if not ValidateSettings then
      Exit;

    AES := CreateAESInstance;
    if AES = nil then
    begin
      DoError('Failed to create AES instance');
      Exit;
    end;

    try
      Result := AES.DecryptPkcs7(Data, FUseRandomIV);
    finally
      AES.Free;
    end;

  except
    on E: Exception do
      DoError('Data decryption failed: ' + E.Message);
  end;
end;

function TmORMotAES.GenerateRandomSalt: string;
var
  SaltBytes: RawByteString;
begin
  // Generate random salt exactly like your working code
  SaltBytes := TAesPrng.Fill(16);
  Result := BinToHex(SaltBytes);
end;

function TmORMotAES.ValidateSettings: Boolean;
begin
  Result := False;

  if FPassword = '' then
  begin
    DoError('Password cannot be empty');
    Exit;
  end;

  if FPBKDF2Iterations < 1000 then
  begin
    DoError('PBKDF2 iterations should be at least 1000');
    Exit;
  end;

  Result := True;
end;

procedure TmORMotAES.ClearSensitiveData;
begin
  FPassword := '';
  FSalt := '';
  FLastResult := '';
  FLastError := '';
end;

end.
