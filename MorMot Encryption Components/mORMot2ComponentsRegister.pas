unit mORMot2ComponentsRegister;

interface

uses
  System.Classes, DesignIntf, DesignEditors,
  mORMot2ComponentsAES,
  mORMot2ComponentsHash,
  mORMot2ComponentsHMAC,
  mORMot2ComponentsPBKDF2,
  mORMot2ComponentsRandom;

// Property editors for enhanced design-time experience
type
  TAESModePropertyEditor = class(TPropertyEditor)
  public
    function GetAttributes: TPropertyAttributes; override;
    procedure GetValues(Proc: TGetStrProc); override;
    function GetValue: string; override;
    procedure SetValue(const Value: string); override;
  end;

  THashAlgorithmPropertyEditor = class(TPropertyEditor)
  public
    function GetAttributes: TPropertyAttributes; override;
    procedure GetValues(Proc: TGetStrProc); override;
    function GetValue: string; override;
    procedure SetValue(const Value: string); override;
  end;

  TPasswordPropertyEditor = class(TPropertyEditor)
  public
    function GetAttributes: TPropertyAttributes; override;
    procedure Edit; override;
    function GetValue: string; override;
    procedure SetValue(const Value: string); override;
  end;

// Component editors for right-click actions
type
  TmORMotCryptoComponentEditor = class(TComponentEditor)
  public
    function GetVerbCount: Integer; override;
    function GetVerb(Index: Integer): string; override;
    procedure ExecuteVerb(Index: Integer); override;
  end;

procedure Register;

implementation

uses
  System.SysUtils, System.TypInfo, Dialogs, Forms, Controls, StdCtrls;

// Property Editors Implementation

function TAESModePropertyEditor.GetAttributes: TPropertyAttributes;
begin
  Result := [paValueList, paSortList, paMultiSelect];
end;

procedure TAESModePropertyEditor.GetValues(Proc: TGetStrProc);
begin
  Proc('ECB (Not Recommended)');
  Proc('CBC (Recommended)');
  Proc('CFB');
  Proc('OFB');
  Proc('CTR');
  Proc('GCM (AEAD)');
  Proc('CFC (mORMot AEAD)');
  Proc('OFC (mORMot AEAD)');
  Proc('CTC (mORMot AEAD)');
end;

function TAESModePropertyEditor.GetValue: string;
var
  Mode: TAESMode;
begin
  Mode := TAESMode(GetOrdValue);
  case Mode of
    amECB: Result := 'ECB (Not Recommended)';
    amCBC: Result := 'CBC (Recommended)';
    amCFB: Result := 'CFB';
    amOFB: Result := 'OFB';
    amCTR: Result := 'CTR';
    amGCM: Result := 'GCM (AEAD)';
    amCFC: Result := 'CFC (mORMot AEAD)';
    amOFC: Result := 'OFC (mORMot AEAD)';
    amCTC: Result := 'CTC (mORMot AEAD)';
  else
    Result := 'Unknown';
  end;
end;

procedure TAESModePropertyEditor.SetValue(const Value: string);
var
  Mode: TAESMode;
begin
  if Value.StartsWith('ECB') then Mode := amECB
  else if Value.StartsWith('CBC') then Mode := amCBC
  else if Value.StartsWith('CFB') then Mode := amCFB
  else if Value.StartsWith('OFB') then Mode := amOFB
  else if Value.StartsWith('CTR') then Mode := amCTR
  else if Value.StartsWith('GCM') then Mode := amGCM
  else if Value.StartsWith('CFC') then Mode := amCFC
  else if Value.StartsWith('OFC') then Mode := amOFC
  else if Value.StartsWith('CTC') then Mode := amCTC
  else Mode := amCBC;

  SetOrdValue(Ord(Mode));
end;

function THashAlgorithmPropertyEditor.GetAttributes: TPropertyAttributes;
begin
  Result := [paValueList, paSortList, paMultiSelect];
end;

procedure THashAlgorithmPropertyEditor.GetValues(Proc: TGetStrProc);
begin
  Proc('MD5 (Broken - Not Recommended)');
  Proc('SHA-1 (Weak - Not Recommended)');
  Proc('SHA-256 (Recommended)');
  Proc('SHA-384 (High Security)');
  Proc('SHA-512 (High Security)');
  Proc('SHA-3-256 (Modern Standard)');
  Proc('SHA-3-512 (Modern High Security)');
end;

function THashAlgorithmPropertyEditor.GetValue: string;
var
  Algo: THashAlgorithm;
begin
  Algo := THashAlgorithm(GetOrdValue);
  case Algo of
    haMD5: Result := 'MD5 (Broken - Not Recommended)';
    haSHA1: Result := 'SHA-1 (Weak - Not Recommended)';
    haSHA256: Result := 'SHA-256 (Recommended)';
    haSHA384: Result := 'SHA-384 (High Security)';
    haSHA512: Result := 'SHA-512 (High Security)';
    haSHA3_256: Result := 'SHA-3-256 (Modern Standard)';
    haSHA3_512: Result := 'SHA-3-512 (Modern High Security)';
  else
    Result := 'Unknown';
  end;
end;

procedure THashAlgorithmPropertyEditor.SetValue(const Value: string);
var
  Algo: THashAlgorithm;
begin
  if Value.StartsWith('MD5') then Algo := haMD5
  else if Value.StartsWith('SHA-1') then Algo := haSHA1
  else if Value.StartsWith('SHA-256') then Algo := haSHA256
  else if Value.StartsWith('SHA-384') then Algo := haSHA384
  else if Value.StartsWith('SHA-512') then Algo := haSHA512
  else if Value.StartsWith('SHA-3-256') then Algo := haSHA3_256
  else if Value.StartsWith('SHA-3-512') then Algo := haSHA3_512
  else Algo := haSHA256;

  SetOrdValue(Ord(Algo));
end;

function TPasswordPropertyEditor.GetValue: string;
begin
  Result := inherited GetValue;
end;

procedure TPasswordPropertyEditor.SetValue(const Value: string);
begin
  inherited SetValue(Value);
end;

function TPasswordPropertyEditor.GetAttributes: TPropertyAttributes;
begin
  Result := [paDialog];
end;

procedure TPasswordPropertyEditor.Edit;
var
  Password: string;
begin
  Password := GetValue;
  if InputQuery('Password', 'Enter password:', Password) then
    SetValue(Password);
end;

// Component Editor Implementation

function TmORMotCryptoComponentEditor.GetVerbCount: Integer;
begin
  if Component is TmORMotAES then
    Result := 4
  else if Component is TmORMotHash then
    Result := 3
  else if Component is TmORMotHMAC then
    Result := 3
  else if Component is TmORMotPBKDF2 then
    Result := 3
  else if Component is TmORMotRandom then
    Result := 4
  else
    Result := 1;
end;

function TmORMotCryptoComponentEditor.GetVerb(Index: Integer): string;
begin
  if Component is TmORMotAES then
  begin
    case Index of
      0: Result := 'Test Encryption...';
      1: Result := 'Generate Random Salt';
      2: Result := 'Clear Sensitive Data';
      3: Result := 'About mORMot2 AES...';
    end;
  end
  else if Component is TmORMotHash then
  begin
    case Index of
      0: Result := 'Test Hash Generation...';
      1: Result := 'Clear Results';
      2: Result := 'About mORMot2 Hash...';
    end;
  end
  else if Component is TmORMotHMAC then
  begin
    case Index of
      0: Result := 'Test HMAC Generation...';
      1: Result := 'Generate Random Key';
      2: Result := 'About mORMot2 HMAC...';
    end;
  end
  else if Component is TmORMotPBKDF2 then
  begin
    case Index of
      0: Result := 'Test Key Derivation...';
      1: Result := 'Generate Random Salt';
      2: Result := 'About mORMot2 PBKDF2...';
    end;
  end
  else if Component is TmORMotRandom then
  begin
    case Index of
      0: Result := 'Generate Test Data...';
      1: Result := 'Test Randomness Quality';
      2: Result := 'Clear Results';
      3: Result := 'About mORMot2 Random...';
    end;
  end
  else
    Result := 'About mORMot2 Components...';
end;

procedure TmORMotCryptoComponentEditor.ExecuteVerb(Index: Integer);
var
  TestResult: string;
  TestData: RawByteString;
begin
  if Component is TmORMotAES then
  begin
    case Index of
      0: begin
           try
             TestResult := (Component as TmORMotAES).EncryptText('Hello, mORMot2!');
             if TestResult <> '' then
               ShowMessage('Test encryption successful!'#13#10'Result: ' + TestResult)
             else
               ShowMessage('Test encryption failed: ' + (Component as TmORMotAES).LastError);
           except
             on E: Exception do
               ShowMessage('Test encryption failed: ' + E.Message);
           end;
         end;
      1: begin
           try
             TestResult := (Component as TmORMotAES).GenerateRandomSalt;
             if TestResult <> '' then
             begin
               (Component as TmORMotAES).Salt := TestResult;
               ShowMessage('Random salt generated and assigned:'#13#10 + TestResult);
             end
             else
               ShowMessage('Salt generation failed: ' + (Component as TmORMotAES).LastError);
           except
             on E: Exception do
               ShowMessage('Salt generation failed: ' + E.Message);
           end;
         end;
      2: begin
           try
             (Component as TmORMotAES).ClearSensitiveData;
             ShowMessage('Sensitive data cleared.');
           except
             on E: Exception do
               ShowMessage('Clear failed: ' + E.Message);
           end;
         end;
      3: ShowMessage('mORMot2 AES Component'#13#10#13#10 +
                     'Provides comprehensive AES encryption/decryption with:'#13#10 +
                     '• Multiple AES modes (CBC, GCM, CFC, OFC, CTC, etc.)'#13#10 +
                     '• 128/192/256-bit key support'#13#10 +
                     '• PBKDF2 key derivation'#13#10 +
                     '• Base64/Hex output encoding'#13#10#13#10 +
                     'Part of the mORMot2 Cryptography Components package.');
    end;
  end
  else if Component is TmORMotHash then
  begin
    case Index of
      0: begin
           try
             TestResult := (Component as TmORMotHash).HashText('Hello, mORMot2!');
             if TestResult <> '' then
               ShowMessage('Test hash successful!'#13#10'Result: ' + TestResult)
             else
               ShowMessage('Test hash failed: ' + (Component as TmORMotHash).LastError);
           except
             on E: Exception do
               ShowMessage('Test hash failed: ' + E.Message);
           end;
         end;
      1: begin
           try
             (Component as TmORMotHash).ClearResults;
             ShowMessage('Results cleared.');
           except
             on E: Exception do
               ShowMessage('Clear failed: ' + E.Message);
           end;
         end;
      2: ShowMessage('mORMot2 Hash Component'#13#10#13#10 +
                     'Provides cryptographic hashing with:'#13#10 +
                     '• MD5, SHA-1, SHA-256/384/512'#13#10 +
                     '• SHA-3-256/512 support'#13#10 +
                     '• File and stream hashing'#13#10 +
                     '• Multiple output encodings'#13#10#13#10 +
                     'Part of the mORMot2 Cryptography Components package.');
    end;
  end
  else if Component is TmORMotHMAC then
  begin
    case Index of
      0: begin
           try
             TestResult := (Component as TmORMotHMAC).CalculateHMAC('Hello, mORMot2!', 'secret');
             if TestResult <> '' then
               ShowMessage('Test HMAC successful!'#13#10'Result: ' + TestResult)
             else
               ShowMessage('Test HMAC failed: ' + (Component as TmORMotHMAC).LastError);
           except
             on E: Exception do
               ShowMessage('Test HMAC failed: ' + E.Message);
           end;
         end;
      1: begin
           try
             TestResult := (Component as TmORMotHMAC).GenerateRandomKey(32);
             if TestResult <> '' then
             begin
               (Component as TmORMotHMAC).SecretKey := TestResult;
               ShowMessage('Random key generated and assigned:'#13#10 + TestResult);
             end
             else
               ShowMessage('Key generation failed: ' + (Component as TmORMotHMAC).LastError);
           except
             on E: Exception do
               ShowMessage('Key generation failed: ' + E.Message);
           end;
         end;
      2: ShowMessage('mORMot2 HMAC Component'#13#10#13#10 +
                     'Provides HMAC authentication with:'#13#10 +
                     '• HMAC-SHA256 support'#13#10 +
                     '• Message verification'#13#10 +
                     '• File and stream HMAC'#13#10 +
                     '• Random key generation'#13#10#13#10 +
                     'Part of the mORMot2 Cryptography Components package.');
    end;
  end
  else if Component is TmORMotPBKDF2 then
  begin
    case Index of
      0: begin
           try
             TestResult := (Component as TmORMotPBKDF2).DeriveKey('password', 'salt', 10000, 32);
             if TestResult <> '' then
               ShowMessage('Test key derivation successful!'#13#10'Result: ' + TestResult)
             else
               ShowMessage('Test key derivation failed: ' + (Component as TmORMotPBKDF2).LastError);
           except
             on E: Exception do
               ShowMessage('Test key derivation failed: ' + E.Message);
           end;
         end;
      1: begin
           try
             TestResult := (Component as TmORMotPBKDF2).GenerateRandomSalt(16);
             if TestResult <> '' then
             begin
               (Component as TmORMotPBKDF2).Salt := TestResult;
               ShowMessage('Random salt generated and assigned:'#13#10 + TestResult);
             end
             else
               ShowMessage('Salt generation failed: ' + (Component as TmORMotPBKDF2).LastError);
           except
             on E: Exception do
               ShowMessage('Salt generation failed: ' + E.Message);
           end;
         end;
      2: ShowMessage('mORMot2 PBKDF2 Component'#13#10#13#10 +
                     'Provides password-based key derivation with:'#13#10 +
                     '• PBKDF2-HMAC-SHA256 support'#13#10 +
                     '• Configurable iterations'#13#10 +
                     '• Password verification'#13#10 +
                     '• Security recommendations'#13#10#13#10 +
                     'Part of the mORMot2 Cryptography Components package.');
    end;
  end
  else if Component is TmORMotRandom then
  begin
    case Index of
      0: begin
           try
             TestResult := (Component as TmORMotRandom).GenerateRandom(32);
             if TestResult <> '' then
               ShowMessage('Test random generation successful!'#13#10'Result: ' + TestResult)
             else
               ShowMessage('Test random generation failed: ' + (Component as TmORMotRandom).LastError);
           except
             on E: Exception do
               ShowMessage('Test random generation failed: ' + E.Message);
           end;
         end;
      1: begin
           try
             TestData := (Component as TmORMotRandom).GenerateRandomData(1024);
             if Length(TestData) > 0 then
             begin
               if (Component as TmORMotRandom).IsRandomnessGood(TestData) then
                 ShowMessage('Randomness quality test: PASSED'#13#10'Entropy: ' +
                            FloatToStrF((Component as TmORMotRandom).TestRandomness(TestData), ffFixed, 3, 2) + ' bits/byte')
               else
                 ShowMessage('Randomness quality test: FAILED'#13#10'Entropy: ' +
                            FloatToStrF((Component as TmORMotRandom).TestRandomness(TestData), ffFixed, 3, 2) + ' bits/byte');
             end
             else
               ShowMessage('Randomness test failed: No data generated');
           except
             on E: Exception do
               ShowMessage('Randomness test failed: ' + E.Message);
           end;
         end;
      2: begin
           try
             ShowMessage('Results cleared.');
           except
             on E: Exception do
               ShowMessage('Clear failed: ' + E.Message);
           end;
         end;
      3: ShowMessage('mORMot2 Random Component'#13#10#13#10 +
                     'Provides cryptographically secure random generation:'#13#10 +
                     '• Random bytes, passwords, keys'#13#10 +
                     '• UUID4 generation'#13#10 +
                     '• Secure tokens and salts'#13#10 +
                     '• Randomness quality testing'#13#10#13#10 +
                     'Part of the mORMot2 Cryptography Components package.');
    end;
  end;
end;

// Registration procedure
procedure Register;
begin
  // Register all components on the 'mORMot2 Crypto' palette
  RegisterComponents('mORMot2 Crypto', [
    TmORMotAES,
    TmORMotHash,
    TmORMotHMAC,
    TmORMotPBKDF2,
    TmORMotRandom
  ]);

  // Register property editors for enhanced design-time experience
  RegisterPropertyEditor(TypeInfo(TAESMode), TmORMotAES, 'AESMode', TAESModePropertyEditor);
  RegisterPropertyEditor(TypeInfo(THashAlgorithm), TmORMotHash, 'HashAlgorithm', THashAlgorithmPropertyEditor);
  RegisterPropertyEditor(TypeInfo(string), TmORMotAES, 'Password', TPasswordPropertyEditor);
  RegisterPropertyEditor(TypeInfo(string), TmORMotHMAC, 'SecretKey', TPasswordPropertyEditor);
  RegisterPropertyEditor(TypeInfo(string), TmORMotPBKDF2, 'Password', TPasswordPropertyEditor);

  // Register component editors for right-click context menus
  RegisterComponentEditor(TmORMotAES, TmORMotCryptoComponentEditor);
  RegisterComponentEditor(TmORMotHash, TmORMotCryptoComponentEditor);
  RegisterComponentEditor(TmORMotHMAC, TmORMotCryptoComponentEditor);
  RegisterComponentEditor(TmORMotPBKDF2, TmORMotCryptoComponentEditor);
  RegisterComponentEditor(TmORMotRandom, TmORMotCryptoComponentEditor);
end;

end.
