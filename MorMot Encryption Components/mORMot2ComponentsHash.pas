unit mORMot2ComponentsHash;

interface

uses
  System.Classes, System.SysUtils,
  mormot.core.base, mormot.core.text, mormot.core.buffers, mormot.crypt.core, mormot.crypt.secure;

type
  THashAlgorithm = (haMD5, haSHA1, haSHA256, haSHA384, haSHA512, haSHA3_256, haSHA3_512);
  TOutputEncoding = (oeBase64, oeHexadecimal, oeLowerHex, oeUpperHex);

  TmORMotHash = class(TComponent)
  private
    FHashAlgorithm: THashAlgorithm;
    FOutputEncoding: TOutputEncoding;
    FInputText: string;
    FOnHashComplete: TNotifyEvent;
    FOnError: TNotifyEvent;
    FLastError: string;
    FLastHash: string;
    FPerformanceMs: Cardinal;
    FHashLength: Integer;

    function GetHashAlgorithmText: string;
    function GetRecommendedUse: string;
    function GetSecurityLevel: string;
    procedure SetHashAlgorithm(const Value: THashAlgorithm);
    function EncodeOutput(const Data: RawByteString): string;
    procedure UpdateHashLength;
  protected
    procedure DoHashComplete; virtual;
    procedure DoError(const ErrorMsg: string); virtual;
  public
    constructor Create(AOwner: TComponent); override;

    // Main hashing methods
    function HashText(const InputText: string = ''): string;
    function HashData(const Data: RawByteString): string;
    function HashFile(const FileName: string): string;
    function HashStream(Stream: TStream): string;

    // Verification methods
    function VerifyText(const InputText, ExpectedHash: string): Boolean;
    function VerifyFile(const FileName, ExpectedHash: string): Boolean;

    // Utility methods
    function CompareHashes(const Hash1, Hash2: string): Boolean;
    procedure ClearResults;

    // Properties (read-only)
    property LastError: string read FLastError;
    property LastHash: string read FLastHash;
    property PerformanceMs: Cardinal read FPerformanceMs;
    property HashAlgorithmText: string read GetHashAlgorithmText;
    property RecommendedUse: string read GetRecommendedUse;
    property SecurityLevel: string read GetSecurityLevel;
    property HashLength: Integer read FHashLength;

  published
    property HashAlgorithm: THashAlgorithm read FHashAlgorithm write SetHashAlgorithm default haSHA256;
    property OutputEncoding: TOutputEncoding read FOutputEncoding write FOutputEncoding default oeHexadecimal;
    property InputText: string read FInputText write FInputText;

    // Events
    property OnHashComplete: TNotifyEvent read FOnHashComplete write FOnHashComplete;
    property OnError: TNotifyEvent read FOnError write FOnError;
  end;

implementation

{ TmORMotHash }

constructor TmORMotHash.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FHashAlgorithm := haSHA256;
  FOutputEncoding := oeHexadecimal;
  FInputText := '';
  FLastError := '';
  FLastHash := '';
  UpdateHashLength;
end;

procedure TmORMotHash.DoHashComplete;
begin
  if Assigned(FOnHashComplete) then
    FOnHashComplete(Self);
end;

procedure TmORMotHash.DoError(const ErrorMsg: string);
begin
  FLastError := ErrorMsg;
  if Assigned(FOnError) then
    FOnError(Self);
end;

function TmORMotHash.GetHashAlgorithmText: string;
begin
  case FHashAlgorithm of
    haMD5: Result := 'MD5';
    haSHA1: Result := 'SHA-1';
    haSHA256: Result := 'SHA-256';
    haSHA384: Result := 'SHA-384';
    haSHA512: Result := 'SHA-512';
    haSHA3_256: Result := 'SHA-3-256';
    haSHA3_512: Result := 'SHA-3-512';
  else
    Result := 'Unknown';
  end;
end;

function TmORMotHash.GetRecommendedUse: string;
begin
  case FHashAlgorithm of
    haMD5: Result := 'Legacy only - NOT RECOMMENDED (cryptographically broken)';
    haSHA1: Result := 'Legacy only - NOT RECOMMENDED (deprecated for security)';
    haSHA256: Result := 'General purpose - RECOMMENDED';
    haSHA384: Result := 'High security applications';
    haSHA512: Result := 'High security applications';
    haSHA3_256: Result := 'Modern applications - Latest standard';
    haSHA3_512: Result := 'High security modern applications - Latest standard';
  else
    Result := 'Unknown';
  end;
end;

function TmORMotHash.GetSecurityLevel: string;
begin
  case FHashAlgorithm of
    haMD5: Result := 'BROKEN';
    haSHA1: Result := 'WEAK';
    haSHA256: Result := 'STRONG';
    haSHA384: Result := 'VERY STRONG';
    haSHA512: Result := 'VERY STRONG';
    haSHA3_256: Result := 'STRONG';
    haSHA3_512: Result := 'VERY STRONG';
  else
    Result := 'UNKNOWN';
  end;
end;

procedure TmORMotHash.SetHashAlgorithm(const Value: THashAlgorithm);
begin
  if FHashAlgorithm <> Value then
  begin
    FHashAlgorithm := Value;
    UpdateHashLength;
    FLastHash := '';
    FLastError := '';
  end;
end;

procedure TmORMotHash.UpdateHashLength;
begin
  case FHashAlgorithm of
    haMD5: FHashLength := 128;
    haSHA1: FHashLength := 160;
    haSHA256: FHashLength := 256;
    haSHA384: FHashLength := 384;
    haSHA512: FHashLength := 512;
    haSHA3_256: FHashLength := 256;
    haSHA3_512: FHashLength := 512;
  else
    FHashLength := 0;
  end;
end;

function TmORMotHash.EncodeOutput(const Data: RawByteString): string;
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

function TmORMotHash.HashText(const InputText: string): string;
var
  StartTime: TDateTime;
  TextToHash: string;
  Input: RawByteString;
  ElapsedMs: Double;
begin
  Result := '';
  FLastError := '';

  try
    StartTime := Now;

    if InputText <> '' then
      TextToHash := InputText
    else
      TextToHash := FInputText;

    if TextToHash = '' then
    begin
      DoError('Input text cannot be empty');
      Exit;
    end;

    // Convert to UTF-8 bytes exactly like your working code
    Input := ToUtf8(TextToHash);

    // Use mORMot2 hash functions exactly like your working code
    case FHashAlgorithm of
      haMD5:
        begin
          var MD5Hash: TMd5Digest;
          MD5Hash := Md5Buf(pointer(Input)^, Length(Input));
          Result := BinToHex(@MD5Hash, SizeOf(MD5Hash));
        end;
      haSHA1:
        begin
          var SHA1: TSha1;
          var SHA1Hash: TSha1Digest;
          SHA1.Full(pointer(Input), Length(Input), SHA1Hash);
          Result := BinToHex(@SHA1Hash, SizeOf(SHA1Hash));
        end;
      haSHA256:
        begin
          var SHA256Hash: TSha256Digest;
          SHA256Hash := Sha256Digest(pointer(Input), Length(Input));
          Result := BinToHex(@SHA256Hash, SizeOf(SHA256Hash));
        end;
      haSHA384:
        begin
          var SHA: TSha384;
          var SHA384Hash: TSha384Digest;
          SHA.Full(pointer(Input), Length(Input), SHA384Hash);
          Result := BinToHex(@SHA384Hash, SizeOf(SHA384Hash));
        end;
      haSHA512:
        begin
          var SHA: TSha512;
          var SHA512Hash: TSha512Digest;
          SHA.Full(pointer(Input), Length(Input), SHA512Hash);
          Result := BinToHex(@SHA512Hash, SizeOf(SHA512Hash));
        end;
      haSHA3_256:
        begin
          var SHA3: TSha3;
          var SHA3Hash: THash256;
          SHA3.Full(SHA3_256, pointer(Input), Length(Input), @SHA3Hash, 256);
          Result := BinToHex(@SHA3Hash, SizeOf(SHA3Hash));
        end;
      haSHA3_512:
        begin
          var SHA3: TSha3;
          var SHA3Hash512: THash512;
          SHA3.Full(SHA3_512, pointer(Input), Length(Input), @SHA3Hash512, 512);
          Result := BinToHex(@SHA3Hash512, SizeOf(SHA3Hash512));
        end;
    else
      begin
        DoError('Unsupported hash algorithm');
        Exit;
      end;
    end;

    // Apply output encoding if not already hex
    if FOutputEncoding <> oeHexadecimal then
      Result := EncodeOutput(HexToBin(Result));

    FLastHash := Result;

    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoHashComplete;

  except
    on E: Exception do
      DoError('Hashing failed: ' + E.Message);
  end;
end;

function TmORMotHash.HashData(const Data: RawByteString): string;
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
      DoError('Input data cannot be empty');
      Exit;
    end;

    case FHashAlgorithm of
      haMD5:
        begin
          var MD5Hash: TMd5Digest;
          MD5Hash := Md5Buf(pointer(Data)^, Length(Data));
          Result := BinToHex(@MD5Hash, SizeOf(MD5Hash));
        end;
      haSHA1:
        begin
          var SHA1: TSha1;
          var SHA1Hash: TSha1Digest;
          SHA1.Full(pointer(Data), Length(Data), SHA1Hash);
          Result := BinToHex(@SHA1Hash, SizeOf(SHA1Hash));
        end;
      haSHA256:
        begin
          var SHA256Hash: TSha256Digest;
          SHA256Hash := Sha256Digest(pointer(Data), Length(Data));
          Result := BinToHex(@SHA256Hash, SizeOf(SHA256Hash));
        end;
      haSHA384:
        begin
          var SHA: TSha384;
          var SHA384Hash: TSha384Digest;
          SHA.Full(pointer(Data), Length(Data), SHA384Hash);
          Result := BinToHex(@SHA384Hash, SizeOf(SHA384Hash));
        end;
      haSHA512:
        begin
          var SHA: TSha512;
          var SHA512Hash: TSha512Digest;
          SHA.Full(pointer(Data), Length(Data), SHA512Hash);
          Result := BinToHex(@SHA512Hash, SizeOf(SHA512Hash));
        end;
      haSHA3_256:
        begin
          var SHA3: TSha3;
          var SHA3Hash: THash256;
          SHA3.Full(SHA3_256, pointer(Data), Length(Data), @SHA3Hash, 256);
          Result := BinToHex(@SHA3Hash, SizeOf(SHA3Hash));
        end;
      haSHA3_512:
        begin
          var SHA3: TSha3;
          var SHA3Hash512: THash512;
          SHA3.Full(SHA3_512, pointer(Data), Length(Data), @SHA3Hash512, 512);
          Result := BinToHex(@SHA3Hash512, SizeOf(SHA3Hash512));
        end;
    else
      begin
        DoError('Unsupported hash algorithm');
        Exit;
      end;
    end;

    if FOutputEncoding <> oeHexadecimal then
      Result := EncodeOutput(HexToBin(Result));

    FLastHash := Result;

    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;
    FPerformanceMs := Trunc(ElapsedMs);
    DoHashComplete;

  except
    on E: Exception do
      DoError('Data hashing failed: ' + E.Message);
  end;
end;

function TmORMotHash.HashFile(const FileName: string): string;
var
  StartTime: TDateTime;
  FileStream: TFileStream;
  Buffer: array[0..8191] of Byte;
  BytesRead: Integer;
  ElapsedMs: Double;
  // Fixed: Use the same approach as HashData for large file hashing
  FileData: RawByteString;
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

    FileStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      // Read entire file into memory for hashing
      // For very large files, you might want to implement streaming hash
      SetLength(FileData, FileStream.Size);
      if FileStream.Size > 0 then
        FileStream.ReadBuffer(FileData[1], FileStream.Size);

      // Use the same logic as HashData
      Result := HashData(FileData);

    finally
      FileStream.Free;
    end;

  except
    on E: Exception do
      DoError('File hashing failed: ' + E.Message);
  end;
end;

function TmORMotHash.HashStream(Stream: TStream): string;
var
  StartTime: TDateTime;
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

    OriginalPosition := Stream.Position;
    Stream.Position := 0;

    try
      // Read entire stream into memory
      SetLength(StreamData, Stream.Size);
      if Stream.Size > 0 then
        Stream.ReadBuffer(StreamData[1], Stream.Size);

      // Use the same logic as HashData
      Result := HashData(StreamData);

    finally
      Stream.Position := OriginalPosition;
    end;

  except
    on E: Exception do
      DoError('Stream hashing failed: ' + E.Message);
  end;
end;

function TmORMotHash.VerifyText(const InputText, ExpectedHash: string): Boolean;
var
  ComputedHash: string;
begin
  Result := False;

  try
    ComputedHash := HashText(InputText);
    if ComputedHash <> '' then
      Result := CompareHashes(ComputedHash, ExpectedHash);
  except
    on E: Exception do
      DoError('Text verification failed: ' + E.Message);
  end;
end;

function TmORMotHash.VerifyFile(const FileName, ExpectedHash: string): Boolean;
var
  ComputedHash: string;
begin
  Result := False;

  try
    ComputedHash := HashFile(FileName);
    if ComputedHash <> '' then
      Result := CompareHashes(ComputedHash, ExpectedHash);
  except
    on E: Exception do
      DoError('File verification failed: ' + E.Message);
  end;
end;

function TmORMotHash.CompareHashes(const Hash1, Hash2: string): Boolean;
begin
  Result := SameText(Hash1, Hash2);
end;

procedure TmORMotHash.ClearResults;
begin
  FLastHash := '';
  FLastError := '';
  FPerformanceMs := 0;
end;

end.
