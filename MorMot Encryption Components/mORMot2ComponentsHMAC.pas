unit mORMot2ComponentsHMAC;

interface

uses
  System.Classes, System.SysUtils,
  mormot.core.base, mormot.core.text, mormot.core.buffers, mormot.crypt.core, mormot.crypt.secure;

type
  THMACAlgorithm = (hmacSHA1, hmacSHA256, hmacSHA384, hmacSHA512, hmacSHA3_256, hmacSHA3_512);
  TOutputEncoding = (oeBase64, oeHexadecimal, oeLowerHex, oeUpperHex);

  TmORMotHMAC = class(TComponent)
  private
    FHMACAlgorithm: THMACAlgorithm;
    FOutputEncoding: TOutputEncoding;
    FSecretKey: string;
    FMessage: string;
    FOnHMACComplete: TNotifyEvent;
    FOnError: TNotifyEvent;
    FLastError: string;
    FLastHMAC: string;
    FPerformanceMs: Cardinal;
    FHMACLength: Integer;

    function GetHMACAlgorithmText: string;
    function GetRecommendedUse: string;
    function GetSecurityLevel: string;
    procedure SetHMACAlgorithm(const Value: THMACAlgorithm);
    function EncodeOutput(const Data: RawByteString): string;
    procedure UpdateHMACLength;
  protected
    procedure DoHMACComplete; virtual;
    procedure DoError(const ErrorMsg: string); virtual;
  public
    constructor Create(AOwner: TComponent); override;

    function CalculateHMAC(const Message: string = ''; const Key: string = ''): string;
    function CalculateHMACData(const Data: RawByteString; const Key: RawByteString): string;
    function CalculateHMACFile(const FileName: string; const Key: string): string;
    function CalculateHMACStream(Stream: TStream; const Key: string): string;

    function VerifyHMAC(const Message, Key, ExpectedHMAC: string): Boolean;
    function VerifyHMACData(const Data, Key: RawByteString; const ExpectedHMAC: string): Boolean;
    function VerifyHMACFile(const FileName, Key, ExpectedHMAC: string): Boolean;

    function CompareHMACs(const HMAC1, HMAC2: string): Boolean;
    function GenerateRandomKey(KeyLength: Integer = 32): string;
    procedure ClearSensitiveData;
    procedure ClearResults;

    property LastError: string read FLastError;
    property LastHMAC: string read FLastHMAC;
    property PerformanceMs: Cardinal read FPerformanceMs;
    property HMACAlgorithmText: string read GetHMACAlgorithmText;
    property RecommendedUse: string read GetRecommendedUse;
    property SecurityLevel: string read GetSecurityLevel;
    property HMACLength: Integer read FHMACLength;

  published
    property HMACAlgorithm: THMACAlgorithm read FHMACAlgorithm write SetHMACAlgorithm default hmacSHA256;
    property OutputEncoding: TOutputEncoding read FOutputEncoding write FOutputEncoding default oeHexadecimal;
    property SecretKey: string read FSecretKey write FSecretKey;
    property Message: string read FMessage write FMessage;

    property OnHMACComplete: TNotifyEvent read FOnHMACComplete write FOnHMACComplete;
    property OnError: TNotifyEvent read FOnError write FOnError;
  end;

implementation

uses
  mormot.core.datetime;

{ TmORMotHMAC }

constructor TmORMotHMAC.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FHMACAlgorithm := hmacSHA256;
  FOutputEncoding := oeHexadecimal;
  FSecretKey := '';
  FMessage := '';
  FLastError := '';
  FLastHMAC := '';
  UpdateHMACLength;
end;

procedure TmORMotHMAC.DoHMACComplete;
begin
  if Assigned(FOnHMACComplete) then
    FOnHMACComplete(Self);
end;

procedure TmORMotHMAC.DoError(const ErrorMsg: string);
begin
  FLastError := ErrorMsg;
  if Assigned(FOnError) then
    FOnError(Self);
end;

function TmORMotHMAC.GetHMACAlgorithmText: string;
begin
  case FHMACAlgorithm of
    hmacSHA1: Result := 'HMAC-SHA1';
    hmacSHA256: Result := 'HMAC-SHA256';
    hmacSHA384: Result := 'HMAC-SHA384';
    hmacSHA512: Result := 'HMAC-SHA512';
    hmacSHA3_256: Result := 'HMAC-SHA3-256';
    hmacSHA3_512: Result := 'HMAC-SHA3-512';
  else
    Result := 'Unknown';
  end;
end;

function TmORMotHMAC.GetRecommendedUse: string;
begin
  case FHMACAlgorithm of
    hmacSHA1: Result := 'Legacy systems only - NOT RECOMMENDED (deprecated)';
    hmacSHA256: Result := 'General purpose - RECOMMENDED';
    hmacSHA384: Result := 'High security applications';
    hmacSHA512: Result := 'High security applications';
    hmacSHA3_256: Result := 'Modern applications - Latest standard';
    hmacSHA3_512: Result := 'High security modern applications - Latest standard';
  else
    Result := 'Unknown';
  end;
end;

function TmORMotHMAC.GetSecurityLevel: string;
begin
  case FHMACAlgorithm of
    hmacSHA1: Result := 'WEAK';
    hmacSHA256: Result := 'STRONG';
    hmacSHA384: Result := 'VERY STRONG';
    hmacSHA512: Result := 'VERY STRONG';
    hmacSHA3_256: Result := 'STRONG';
    hmacSHA3_512: Result := 'VERY STRONG';
  else
    Result := 'UNKNOWN';
  end;
end;

procedure TmORMotHMAC.SetHMACAlgorithm(const Value: THMACAlgorithm);
begin
  if FHMACAlgorithm <> Value then
  begin
    FHMACAlgorithm := Value;
    UpdateHMACLength;
    FLastHMAC := '';
    FLastError := '';
  end;
end;

procedure TmORMotHMAC.UpdateHMACLength;
begin
  case FHMACAlgorithm of
    hmacSHA1: FHMACLength := 160;
    hmacSHA256: FHMACLength := 256;
    hmacSHA384: FHMACLength := 384;
    hmacSHA512: FHMACLength := 512;
    hmacSHA3_256: FHMACLength := 256;
    hmacSHA3_512: FHMACLength := 512;
  else
    FHMACLength := 0;
  end;
end;

function TmORMotHMAC.EncodeOutput(const Data: RawByteString): string;
begin
  try
    case FOutputEncoding of
      oeBase64: Result := BinToBase64(Data);
      oeHexadecimal: Result := LowerCase(BinToHex(Data));
      oeLowerHex: Result := LowerCase(BinToHex(Data));
      oeUpperHex: Result := UpperCase(BinToHex(Data));
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

function TmORMotHMAC.CalculateHMAC(const Message, Key: string): string;
var
  StartTime: TDateTime;
  MessageToUse, KeyToUse: string;
  KeyBytes, MessageBytes: RawByteString;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if Message <> '' then
      MessageToUse := Message
    else
      MessageToUse := FMessage;

    if Key <> '' then
      KeyToUse := Key
    else
      KeyToUse := FSecretKey;

    if MessageToUse = '' then
    begin
      DoError('Message cannot be empty');
      Exit;
    end;

    if KeyToUse = '' then
    begin
      DoError('Secret key cannot be empty');
      Exit;
    end;

    MessageBytes := ToUtf8(MessageToUse);
    KeyBytes := ToUtf8(KeyToUse);

    // Use exact HMAC functions from your working code
    case FHMACAlgorithm of
      hmacSHA256:
        begin
          var HMAC: TSha256Digest;
          mormot.crypt.core.HmacSha256(KeyBytes, MessageBytes, HMAC);
          Result := BinToHex(@HMAC, SizeOf(HMAC));
        end;
      hmacSHA1:
        begin
          DoError('HMAC-SHA1 not available in this mORMot version');
          Exit;
        end;
      hmacSHA384:
        begin
          DoError('HMAC-SHA384 not available in this mORMot version');
          Exit;
        end;
      hmacSHA512:
        begin
          DoError('HMAC-SHA512 not available in this mORMot version');
          Exit;
        end;
      hmacSHA3_256:
        begin
          DoError('HMAC-SHA3-256 not available in this mORMot version');
          Exit;
        end;
      hmacSHA3_512:
        begin
          DoError('HMAC-SHA3-512 not available in this mORMot version');
          Exit;
        end;
    else
      begin
        DoError('Unsupported HMAC algorithm');
        Exit;
      end;
    end;

    if FOutputEncoding <> oeHexadecimal then
      Result := EncodeOutput(HexToBin(Result));

    FLastHMAC := Result;

    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoHMACComplete;

  except
    on E: Exception do
      DoError('HMAC calculation failed: ' + E.Message);
  end;
end;

function TmORMotHMAC.CalculateHMACData(const Data, Key: RawByteString): string;
var
  StartTime: TDateTime;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if Length(Data) = 0 then
    begin
      DoError('Data cannot be empty');
      Exit;
    end;

    if Length(Key) = 0 then
    begin
      DoError('Key cannot be empty');
      Exit;
    end;

    case FHMACAlgorithm of
      hmacSHA256:
        begin
          var HMAC: TSha256Digest;
          mormot.crypt.core.HmacSha256(Key, Data, HMAC);
          Result := BinToHex(@HMAC, SizeOf(HMAC));
        end;
      hmacSHA1:
        begin
          DoError('HMAC-SHA1 not available in this mORMot version');
          Exit;
        end;
      hmacSHA384:
        begin
          DoError('HMAC-SHA384 not available in this mORMot version');
          Exit;
        end;
      hmacSHA512:
        begin
          DoError('HMAC-SHA512 not available in this mORMot version');
          Exit;
        end;
      hmacSHA3_256:
        begin
          DoError('HMAC-SHA3-256 not available in this mORMot version');
          Exit;
        end;
      hmacSHA3_512:
        begin
          DoError('HMAC-SHA3-512 not available in this mORMot version');
          Exit;
        end;
    else
      begin
        DoError('Unsupported HMAC algorithm');
        Exit;
      end;
    end;

    if FOutputEncoding <> oeHexadecimal then
      Result := EncodeOutput(HexToBin(Result));

    FLastHMAC := Result;

    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoHMACComplete;

  except
    on E: Exception do
      DoError('HMAC data calculation failed: ' + E.Message);
  end;
end;

function TmORMotHMAC.CalculateHMACFile(const FileName, Key: string): string;
var
  StartTime: TDateTime;
  FileStream: TFileStream;
  KeyBytes: RawByteString;
  FileData: RawByteString;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if not FileExists(FileName) then
    begin
      DoError('File not found: ' + FileName);
      Exit;
    end;

    if Key = '' then
    begin
      DoError('Key cannot be empty');
      Exit;
    end;

    KeyBytes := ToUtf8(Key);

    FileStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      // Read entire file into memory and use the working HMAC functions
      SetLength(FileData, FileStream.Size);
      if FileStream.Size > 0 then
        FileStream.ReadBuffer(FileData[1], FileStream.Size);

      // Use the same logic as CalculateHMACData
      Result := CalculateHMACData(FileData, KeyBytes);

    finally
      FileStream.Free;
    end;

  except
    on E: Exception do
      DoError('File HMAC calculation failed: ' + E.Message);
  end;
end;

function TmORMotHMAC.CalculateHMACStream(Stream: TStream; const Key: string): string;
var
  StartTime: TDateTime;
  KeyBytes: RawByteString;
  OriginalPosition: Int64;
  StreamData: RawByteString;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if not Assigned(Stream) then
    begin
      DoError('Stream cannot be nil');
      Exit;
    end;

    if Key = '' then
    begin
      DoError('Key cannot be empty');
      Exit;
    end;

    KeyBytes := ToUtf8(Key);
    OriginalPosition := Stream.Position;
    Stream.Position := 0;

    try
      // Read entire stream into memory and use the working HMAC functions
      SetLength(StreamData, Stream.Size);
      if Stream.Size > 0 then
        Stream.ReadBuffer(StreamData[1], Stream.Size);

      // Use the same logic as CalculateHMACData
      Result := CalculateHMACData(StreamData, KeyBytes);

    finally
      Stream.Position := OriginalPosition;
    end;

  except
    on E: Exception do
      DoError('Stream HMAC calculation failed: ' + E.Message);
  end;
end;

function TmORMotHMAC.VerifyHMAC(const Message, Key, ExpectedHMAC: string): Boolean;
var
  ComputedHMAC: string;
begin
  Result := False;

  try
    ComputedHMAC := CalculateHMAC(Message, Key);
    if ComputedHMAC <> '' then
      Result := CompareHMACs(ComputedHMAC, ExpectedHMAC);
  except
    on E: Exception do
      DoError('HMAC verification failed: ' + E.Message);
  end;
end;

function TmORMotHMAC.VerifyHMACData(const Data, Key: RawByteString; const ExpectedHMAC: string): Boolean;
var
  ComputedHMAC: string;
begin
  Result := False;

  try
    ComputedHMAC := CalculateHMACData(Data, Key);
    if ComputedHMAC <> '' then
      Result := CompareHMACs(ComputedHMAC, ExpectedHMAC);
  except
    on E: Exception do
      DoError('HMAC data verification failed: ' + E.Message);
  end;
end;

function TmORMotHMAC.VerifyHMACFile(const FileName, Key, ExpectedHMAC: string): Boolean;
var
  ComputedHMAC: string;
begin
  Result := False;

  try
    ComputedHMAC := CalculateHMACFile(FileName, Key);
    if ComputedHMAC <> '' then
      Result := CompareHMACs(ComputedHMAC, ExpectedHMAC);
  except
    on E: Exception do
      DoError('HMAC file verification failed: ' + E.Message);
  end;
end;

function TmORMotHMAC.CompareHMACs(const HMAC1, HMAC2: string): Boolean;
begin
  Result := SameText(HMAC1, HMAC2);
end;

function TmORMotHMAC.GenerateRandomKey(KeyLength: Integer): string;
var
  KeyBytes: RawByteString;
begin
  try
    if KeyLength < 16 then
      KeyLength := 32;

    KeyBytes := TAesPrng.Fill(KeyLength);
    Result := BinToHex(KeyBytes);
  except
    on E: Exception do
    begin
      DoError('Random key generation failed: ' + E.Message);
      Result := '';
    end;
  end;
end;

procedure TmORMotHMAC.ClearSensitiveData;
begin
  FSecretKey := '';
  FMessage := '';
  FLastHMAC := '';
  FLastError := '';
end;

procedure TmORMotHMAC.ClearResults;
begin
  FLastHMAC := '';
  FLastError := '';
  FPerformanceMs := 0;
end;

end.
