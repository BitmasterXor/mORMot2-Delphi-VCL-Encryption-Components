unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, mORMot2ComponentsRandom,
  mORMot2ComponentsPBKDF2, mORMot2ComponentsHMAC, mORMot2ComponentsHash,
  mORMot2ComponentsAES, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls;

type
  TForm1 = class(TForm)
    mORMotAES1: TmORMotAES;
    mORMotHash1: TmORMotHash;
    mORMotHMAC1: TmORMotHMAC;
    mORMotPBKDF21: TmORMotPBKDF2;
    mORMotRandom1: TmORMotRandom;
    PageControl1: TPageControl;
    TabAES: TTabSheet;
    TabHash: TTabSheet;
    TabHMAC: TTabSheet;
    TabPBKDF2: TTabSheet;
    TabRandom: TTabSheet;
    // AES Tab
    GroupBox1: TGroupBox;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    EditAESPassword: TEdit;
    EditAESPlainText: TEdit;
    ButtonAESEncrypt: TButton;
    ButtonAESDecrypt: TButton;
    ButtonAESGenerateSalt: TButton;
    MemoAESResult: TMemo;
    Label4: TLabel;
    EditAESSalt: TEdit;
    ComboAESMode: TComboBox;
    CheckBoxAESRandomIV: TCheckBox;
    // Hash Tab
    GroupBox2: TGroupBox;
    Label6: TLabel;
    Label7: TLabel;
    EditHashInput: TEdit;
    ComboHashAlgorithm: TComboBox;
    ButtonHashCalculate: TButton;
    ButtonHashFile: TButton;
    MemoHashResult: TMemo;
    OpenDialog1: TOpenDialog;
    // HMAC Tab
    GroupBox3: TGroupBox;
    Label8: TLabel;
    Label9: TLabel;
    EditHMACMessage: TEdit;
    EditHMACKey: TEdit;
    ButtonHMACCalculate: TButton;
    ButtonHMACGenerateKey: TButton;
    ButtonHMACVerify: TButton;
    MemoHMACResult: TMemo;
    Label10: TLabel;
    EditHMACExpected: TEdit;
    // PBKDF2 Tab
    GroupBox4: TGroupBox;
    Label11: TLabel;
    Label12: TLabel;
    Label13: TLabel;
    Label14: TLabel;
    EditPBKDF2Password: TEdit;
    EditPBKDF2Salt: TEdit;
    EditPBKDF2Iterations: TEdit;
    EditPBKDF2KeyLength: TEdit;
    ButtonPBKDF2Derive: TButton;
    ButtonPBKDF2GenerateSalt: TButton;
    ButtonPBKDF2Verify: TButton;
    MemoPBKDF2Result: TMemo;
    // Random Tab
    GroupBox5: TGroupBox;
    Label15: TLabel;
    Label16: TLabel;
    EditRandomLength: TEdit;
    ComboRandomType: TComboBox;
    ButtonRandomGenerate: TButton;
    ButtonRandomPassword: TButton;
    ButtonRandomUUID: TButton;
    ButtonRandomTest: TButton;
    MemoRandomResult: TMemo;
    StatusBar1: TStatusBar;
    procedure FormCreate(Sender: TObject);
    // AES Events
    procedure ButtonAESEncryptClick(Sender: TObject);
    procedure ButtonAESDecryptClick(Sender: TObject);
    procedure ButtonAESGenerateSaltClick(Sender: TObject);
    procedure ComboAESModeChange(Sender: TObject);
    // Hash Events
    procedure ButtonHashCalculateClick(Sender: TObject);
    procedure ButtonHashFileClick(Sender: TObject);
    procedure ComboHashAlgorithmChange(Sender: TObject);
    // HMAC Events
    procedure ButtonHMACCalculateClick(Sender: TObject);
    procedure ButtonHMACGenerateKeyClick(Sender: TObject);
    procedure ButtonHMACVerifyClick(Sender: TObject);
    // PBKDF2 Events
    procedure ButtonPBKDF2DeriveClick(Sender: TObject);
    procedure ButtonPBKDF2GenerateSaltClick(Sender: TObject);
    procedure ButtonPBKDF2VerifyClick(Sender: TObject);
    // Random Events
    procedure ButtonRandomGenerateClick(Sender: TObject);
    procedure ButtonRandomPasswordClick(Sender: TObject);
    procedure ButtonRandomUUIDClick(Sender: TObject);
    procedure ButtonRandomTestClick(Sender: TObject);
    procedure ComboRandomTypeChange(Sender: TObject);
    // Component Events
    procedure mORMotAES1EncryptionComplete(Sender: TObject);
    procedure mORMotAES1DecryptionComplete(Sender: TObject);
    procedure mORMotAES1Error(Sender: TObject);
    procedure mORMotHash1HashComplete(Sender: TObject);
    procedure mORMotHash1Error(Sender: TObject);
    procedure mORMotHMAC1HMACComplete(Sender: TObject);
    procedure mORMotHMAC1Error(Sender: TObject);
    procedure mORMotPBKDF21KeyDerivationComplete(Sender: TObject);
    procedure mORMotPBKDF21Error(Sender: TObject);
    procedure mORMotRandom1RandomGenerated(Sender: TObject);
    procedure mORMotRandom1Error(Sender: TObject);
  private
    procedure UpdateStatus(const Msg: string);
    procedure ShowPerformance(const Component: string; Ms: Cardinal);
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
begin
  // Initialize AES
  ComboAESMode.Items.AddStrings(['CBC (Recommended)', 'ECB (Not Recommended)',
    'CFB', 'OFB', 'CTR', 'GCM (AEAD)', 'CFC (mORMot AEAD)', 'OFC (mORMot AEAD)', 'CTC (mORMot AEAD)']);
  ComboAESMode.ItemIndex := 0; // CBC default
  EditAESPassword.Text := 'MySecretPassword123';
  EditAESPlainText.Text := 'Hello, mORMot2 Cryptography!';
  EditAESSalt.Text := mORMotAES1.Salt;
  CheckBoxAESRandomIV.Checked := mORMotAES1.UseRandomIV;

  // Initialize Hash
  ComboHashAlgorithm.Items.AddStrings(['SHA-256 (Recommended)', 'MD5 (Broken)',
    'SHA-1 (Weak)', 'SHA-384', 'SHA-512', 'SHA-3-256', 'SHA-3-512']);
  ComboHashAlgorithm.ItemIndex := 0; // SHA-256 default
  EditHashInput.Text := 'Hello, mORMot2!';

  // Initialize HMAC
  EditHMACMessage.Text := 'Hello, mORMot2!';
  EditHMACKey.Text := 'secret_key_123';

  // Initialize PBKDF2
  EditPBKDF2Password.Text := 'MyPassword123';
  EditPBKDF2Salt.Text := 'random_salt_16_bytes';
  EditPBKDF2Iterations.Text := '100000';
  EditPBKDF2KeyLength.Text := '32';

  // Initialize Random
  ComboRandomType.Items.AddStrings(['Bytes', 'Password', 'Key', 'Salt', 'UUID', 'Token']);
  ComboRandomType.ItemIndex := 0; // Bytes default
  EditRandomLength.Text := '32';

  // Set component event handlers
  mORMotAES1.OnEncryptionComplete := mORMotAES1EncryptionComplete;
  mORMotAES1.OnDecryptionComplete := mORMotAES1DecryptionComplete;
  mORMotAES1.OnError := mORMotAES1Error;

  mORMotHash1.OnHashComplete := mORMotHash1HashComplete;
  mORMotHash1.OnError := mORMotHash1Error;

  mORMotHMAC1.OnHMACComplete := mORMotHMAC1HMACComplete;
  mORMotHMAC1.OnError := mORMotHMAC1Error;

  mORMotPBKDF21.OnKeyDerivationComplete := mORMotPBKDF21KeyDerivationComplete;
  mORMotPBKDF21.OnError := mORMotPBKDF21Error;

  mORMotRandom1.OnRandomGenerated := mORMotRandom1RandomGenerated;
  mORMotRandom1.OnError := mORMotRandom1Error;

  UpdateStatus('mORMot2 Cryptography Components Demo Ready');
end;

// Helper Methods
procedure TForm1.UpdateStatus(const Msg: string);
begin
  StatusBar1.SimpleText := Msg;
  Application.ProcessMessages;
end;

procedure TForm1.ShowPerformance(const Component: string; Ms: Cardinal);
begin
  UpdateStatus(Format('%s operation completed in %d ms', [Component, Ms]));
end;

// AES Events
procedure TForm1.ComboAESModeChange(Sender: TObject);
begin
  case ComboAESMode.ItemIndex of
    0: mORMotAES1.AESMode := amCBC;
    1: mORMotAES1.AESMode := amECB;
    2: mORMotAES1.AESMode := amCFB;
    3: mORMotAES1.AESMode := amOFB;
    4: mORMotAES1.AESMode := amCTR;
    5: mORMotAES1.AESMode := amGCM;
    6: mORMotAES1.AESMode := amCFC;
    7: mORMotAES1.AESMode := amOFC;
    8: mORMotAES1.AESMode := amCTC;
  end;
end;

procedure TForm1.ButtonAESEncryptClick(Sender: TObject);
begin
  UpdateStatus('Encrypting...');
  mORMotAES1.Password := EditAESPassword.Text;
  mORMotAES1.Salt := EditAESSalt.Text;
  mORMotAES1.UseRandomIV := CheckBoxAESRandomIV.Checked;

  MemoAESResult.Lines.Add('=== ENCRYPTION ===');
  MemoAESResult.Lines.Add('Mode: ' + mORMotAES1.AESModeText);
  MemoAESResult.Lines.Add('Input: ' + EditAESPlainText.Text);

  var Result := mORMotAES1.EncryptText(EditAESPlainText.Text);
  if Result <> '' then
  begin
    MemoAESResult.Lines.Add('Encrypted: ' + Result);
    MemoAESResult.Lines.Add('');
  end;
end;

procedure TForm1.ButtonAESDecryptClick(Sender: TObject);
begin
  UpdateStatus('Decrypting...');
  mORMotAES1.Password := EditAESPassword.Text;
  mORMotAES1.Salt := EditAESSalt.Text;
  mORMotAES1.UseRandomIV := CheckBoxAESRandomIV.Checked;

  // Get the last encrypted result from memo for decryption test
  var EncryptedText := '';
  for var i := MemoAESResult.Lines.Count - 1 downto 0 do
  begin
    if MemoAESResult.Lines[i].StartsWith('Encrypted: ') then
    begin
      EncryptedText := Copy(MemoAESResult.Lines[i], 12, Length(MemoAESResult.Lines[i]));
      Break;
    end;
  end;

  if EncryptedText = '' then
  begin
    ShowMessage('No encrypted text found. Please encrypt something first.');
    Exit;
  end;

  MemoAESResult.Lines.Add('=== DECRYPTION ===');
  MemoAESResult.Lines.Add('Input: ' + EncryptedText);

  var Result := mORMotAES1.DecryptText(EncryptedText);
  if Result <> '' then
  begin
    MemoAESResult.Lines.Add('Decrypted: ' + Result);
    MemoAESResult.Lines.Add('');
  end;
end;

procedure TForm1.ButtonAESGenerateSaltClick(Sender: TObject);
begin
  var Salt := mORMotAES1.GenerateRandomSalt;
  EditAESSalt.Text := Salt;
  UpdateStatus('New salt generated');
end;

// Hash Events
procedure TForm1.ComboHashAlgorithmChange(Sender: TObject);
begin
  case ComboHashAlgorithm.ItemIndex of
    0: mORMotHash1.HashAlgorithm := haSHA256;
    1: mORMotHash1.HashAlgorithm := haMD5;
    2: mORMotHash1.HashAlgorithm := haSHA1;
    3: mORMotHash1.HashAlgorithm := haSHA384;
    4: mORMotHash1.HashAlgorithm := haSHA512;
    5: mORMotHash1.HashAlgorithm := haSHA3_256;
    6: mORMotHash1.HashAlgorithm := haSHA3_512;
  end;
end;

procedure TForm1.ButtonHashCalculateClick(Sender: TObject);
begin
  UpdateStatus('Calculating hash...');
  MemoHashResult.Lines.Add('=== HASH CALCULATION ===');
  MemoHashResult.Lines.Add('Algorithm: ' + mORMotHash1.HashAlgorithmText);
  MemoHashResult.Lines.Add('Input: ' + EditHashInput.Text);

  var Result := mORMotHash1.HashText(EditHashInput.Text);
  if Result <> '' then
  begin
    MemoHashResult.Lines.Add('Hash: ' + Result);
    MemoHashResult.Lines.Add('Security: ' + mORMotHash1.SecurityLevel);
    MemoHashResult.Lines.Add('');
  end;
end;

procedure TForm1.ButtonHashFileClick(Sender: TObject);
begin
  if OpenDialog1.Execute then
  begin
    UpdateStatus('Calculating file hash...');
    MemoHashResult.Lines.Add('=== FILE HASH ===');
    MemoHashResult.Lines.Add('Algorithm: ' + mORMotHash1.HashAlgorithmText);
    MemoHashResult.Lines.Add('File: ' + ExtractFileName(OpenDialog1.FileName));

    var Result := mORMotHash1.HashFile(OpenDialog1.FileName);
    if Result <> '' then
    begin
      MemoHashResult.Lines.Add('Hash: ' + Result);
      MemoHashResult.Lines.Add('');
    end;
  end;
end;

// HMAC Events
procedure TForm1.ButtonHMACCalculateClick(Sender: TObject);
begin
  UpdateStatus('Calculating HMAC...');
  MemoHMACResult.Lines.Add('=== HMAC CALCULATION ===');
  MemoHMACResult.Lines.Add('Algorithm: ' + mORMotHMAC1.HMACAlgorithmText);
  MemoHMACResult.Lines.Add('Message: ' + EditHMACMessage.Text);
  MemoHMACResult.Lines.Add('Key: ' + EditHMACKey.Text);

  var Result := mORMotHMAC1.CalculateHMAC(EditHMACMessage.Text, EditHMACKey.Text);
  if Result <> '' then
  begin
    MemoHMACResult.Lines.Add('HMAC: ' + Result);
    MemoHMACResult.Lines.Add('Security: ' + mORMotHMAC1.SecurityLevel);
    MemoHMACResult.Lines.Add('');
  end;
end;

procedure TForm1.ButtonHMACGenerateKeyClick(Sender: TObject);
begin
  var Key := mORMotHMAC1.GenerateRandomKey(32);
  EditHMACKey.Text := Key;
  UpdateStatus('New HMAC key generated');
end;

procedure TForm1.ButtonHMACVerifyClick(Sender: TObject);
begin
  UpdateStatus('Verifying HMAC...');
  var IsValid := mORMotHMAC1.VerifyHMAC(EditHMACMessage.Text, EditHMACKey.Text, EditHMACExpected.Text);

  MemoHMACResult.Lines.Add('=== HMAC VERIFICATION ===');
  MemoHMACResult.Lines.Add('Expected: ' + EditHMACExpected.Text);
  MemoHMACResult.Lines.Add('Result: ' + BoolToStr(IsValid, True));
  MemoHMACResult.Lines.Add('');

  if IsValid then
    UpdateStatus('HMAC verification: VALID')
  else
    UpdateStatus('HMAC verification: INVALID');
end;

// PBKDF2 Events
procedure TForm1.ButtonPBKDF2DeriveClick(Sender: TObject);
begin
  UpdateStatus('Deriving key...');
  MemoPBKDF2Result.Lines.Add('=== KEY DERIVATION ===');
  MemoPBKDF2Result.Lines.Add('Algorithm: ' + mORMotPBKDF21.PBKDF2AlgorithmText);
  MemoPBKDF2Result.Lines.Add('Password: ' + EditPBKDF2Password.Text);
  MemoPBKDF2Result.Lines.Add('Salt: ' + EditPBKDF2Salt.Text);
  MemoPBKDF2Result.Lines.Add('Iterations: ' + EditPBKDF2Iterations.Text);
  MemoPBKDF2Result.Lines.Add('Key Length: ' + EditPBKDF2KeyLength.Text + ' bytes');

  var Result := mORMotPBKDF21.DeriveKey(EditPBKDF2Password.Text, EditPBKDF2Salt.Text,
    StrToIntDef(EditPBKDF2Iterations.Text, 100000), StrToIntDef(EditPBKDF2KeyLength.Text, 32));

  if Result <> '' then
  begin
    MemoPBKDF2Result.Lines.Add('Derived Key: ' + Result);
    MemoPBKDF2Result.Lines.Add('Security: ' + mORMotPBKDF21.SecurityLevel);
    MemoPBKDF2Result.Lines.Add('');
  end;
end;

procedure TForm1.ButtonPBKDF2GenerateSaltClick(Sender: TObject);
begin
  var Salt := mORMotPBKDF21.GenerateRandomSalt(16);
  EditPBKDF2Salt.Text := Salt;
  UpdateStatus('New PBKDF2 salt generated');
end;

procedure TForm1.ButtonPBKDF2VerifyClick(Sender: TObject);
begin
  // Get the last derived key for verification
  var DerivedKey := '';
  for var i := MemoPBKDF2Result.Lines.Count - 1 downto 0 do
  begin
    if MemoPBKDF2Result.Lines[i].StartsWith('Derived Key: ') then
    begin
      DerivedKey := Copy(MemoPBKDF2Result.Lines[i], 14, Length(MemoPBKDF2Result.Lines[i]));
      Break;
    end;
  end;

  if DerivedKey = '' then
  begin
    ShowMessage('No derived key found. Please derive a key first.');
    Exit;
  end;

  UpdateStatus('Verifying password...');
  var IsValid := mORMotPBKDF21.VerifyPassword(EditPBKDF2Password.Text, EditPBKDF2Salt.Text,
    DerivedKey, StrToIntDef(EditPBKDF2Iterations.Text, 100000), StrToIntDef(EditPBKDF2KeyLength.Text, 32));

  MemoPBKDF2Result.Lines.Add('=== PASSWORD VERIFICATION ===');
  MemoPBKDF2Result.Lines.Add('Result: ' + BoolToStr(IsValid, True));
  MemoPBKDF2Result.Lines.Add('');

  if IsValid then
    UpdateStatus('Password verification: VALID')
  else
    UpdateStatus('Password verification: INVALID');
end;

// Random Events
procedure TForm1.ComboRandomTypeChange(Sender: TObject);
begin
  case ComboRandomType.ItemIndex of
    0: mORMotRandom1.DataType := rdtBytes;
    1: mORMotRandom1.DataType := rdtPassword;
    2: mORMotRandom1.DataType := rdtKey;
    3: mORMotRandom1.DataType := rdtSalt;
    4: mORMotRandom1.DataType := rdtUUID;
    5: mORMotRandom1.DataType := rdtToken;
  end;
  EditRandomLength.Text := IntToStr(mORMotRandom1.RecommendedLength);
end;

procedure TForm1.ButtonRandomGenerateClick(Sender: TObject);
begin
  UpdateStatus('Generating random data...');
  MemoRandomResult.Lines.Add('=== RANDOM GENERATION ===');
  MemoRandomResult.Lines.Add('Type: ' + mORMotRandom1.DataTypeDescription);
  MemoRandomResult.Lines.Add('Length: ' + EditRandomLength.Text);

  var Result := mORMotRandom1.GenerateRandom(StrToIntDef(EditRandomLength.Text, 32));
  if Result <> '' then
  begin
    MemoRandomResult.Lines.Add('Result: ' + Result);
    MemoRandomResult.Lines.Add('');
  end;
end;

procedure TForm1.ButtonRandomPasswordClick(Sender: TObject);
begin
  UpdateStatus('Generating password...');
  MemoRandomResult.Lines.Add('=== PASSWORD GENERATION ===');

  var Result := mORMotRandom1.GeneratePassword(StrToIntDef(EditRandomLength.Text, 16));
  if Result <> '' then
  begin
    MemoRandomResult.Lines.Add('Password: ' + Result);
    MemoRandomResult.Lines.Add('Length: ' + IntToStr(Length(Result)));
    MemoRandomResult.Lines.Add('');
  end;
end;

procedure TForm1.ButtonRandomUUIDClick(Sender: TObject);
begin
  UpdateStatus('Generating UUID...');
  MemoRandomResult.Lines.Add('=== UUID GENERATION ===');

  var Result := mORMotRandom1.GenerateUUID;
  if Result <> '' then
  begin
    MemoRandomResult.Lines.Add('UUID: ' + Result);
    MemoRandomResult.Lines.Add('');
  end;
end;

procedure TForm1.ButtonRandomTestClick(Sender: TObject);
begin
  UpdateStatus('Testing randomness quality...');
  var TestData := mORMotRandom1.GenerateRandomData(1024);

  if Length(TestData) > 0 then
  begin
    var Entropy := mORMotRandom1.TestRandomness(TestData);
    var IsGood := mORMotRandom1.IsRandomnessGood(TestData);

    MemoRandomResult.Lines.Add('=== RANDOMNESS TEST ===');
    MemoRandomResult.Lines.Add('Test Data Size: 1024 bytes');
    MemoRandomResult.Lines.Add('Entropy: ' + FloatToStrF(Entropy, ffFixed, 3, 2) + ' bits/byte');
    MemoRandomResult.Lines.Add('Quality: ' + BoolToStr(IsGood, True));
    MemoRandomResult.Lines.Add('Expected: ~8.0 bits/byte for good randomness');
    MemoRandomResult.Lines.Add('');

    if IsGood then
      UpdateStatus('Randomness test: PASSED')
    else
      UpdateStatus('Randomness test: FAILED');
  end;
end;

// Component Event Handlers
procedure TForm1.mORMotAES1EncryptionComplete(Sender: TObject);
begin
  ShowPerformance('AES Encryption', mORMotAES1.PerformanceMs);
end;

procedure TForm1.mORMotAES1DecryptionComplete(Sender: TObject);
begin
  ShowPerformance('AES Decryption', mORMotAES1.PerformanceMs);
end;

procedure TForm1.mORMotAES1Error(Sender: TObject);
begin
  MemoAESResult.Lines.Add('ERROR: ' + mORMotAES1.LastError);
  UpdateStatus('AES Error: ' + mORMotAES1.LastError);
end;

procedure TForm1.mORMotHash1HashComplete(Sender: TObject);
begin
  ShowPerformance('Hash Calculation', mORMotHash1.PerformanceMs);
end;

procedure TForm1.mORMotHash1Error(Sender: TObject);
begin
  MemoHashResult.Lines.Add('ERROR: ' + mORMotHash1.LastError);
  UpdateStatus('Hash Error: ' + mORMotHash1.LastError);
end;

procedure TForm1.mORMotHMAC1HMACComplete(Sender: TObject);
begin
  ShowPerformance('HMAC Calculation', mORMotHMAC1.PerformanceMs);
end;

procedure TForm1.mORMotHMAC1Error(Sender: TObject);
begin
  MemoHMACResult.Lines.Add('ERROR: ' + mORMotHMAC1.LastError);
  UpdateStatus('HMAC Error: ' + mORMotHMAC1.LastError);
end;

procedure TForm1.mORMotPBKDF21KeyDerivationComplete(Sender: TObject);
begin
  ShowPerformance('PBKDF2 Key Derivation', mORMotPBKDF21.PerformanceMs);
end;

procedure TForm1.mORMotPBKDF21Error(Sender: TObject);
begin
  MemoPBKDF2Result.Lines.Add('ERROR: ' + mORMotPBKDF21.LastError);
  UpdateStatus('PBKDF2 Error: ' + mORMotPBKDF21.LastError);
end;

procedure TForm1.mORMotRandom1RandomGenerated(Sender: TObject);
begin
  ShowPerformance('Random Generation', mORMotRandom1.PerformanceMs);
end;

procedure TForm1.mORMotRandom1Error(Sender: TObject);
begin
  MemoRandomResult.Lines.Add('ERROR: ' + mORMotRandom1.LastError);
  UpdateStatus('Random Error: ' + mORMotRandom1.LastError);
end;

end.
