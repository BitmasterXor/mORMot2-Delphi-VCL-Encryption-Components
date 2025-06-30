object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'mORMot2 Cryptography Components Demo'
  ClientHeight = 600
  ClientWidth = 800
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  DesignSize = (
    800
    600)
  TextHeight = 15
  object PageControl1: TPageControl
    Left = 8
    Top = 8
    Width = 784
    Height = 565
    ActivePage = TabAES
    Anchors = [akLeft, akTop, akRight, akBottom]
    TabOrder = 0
    object TabAES: TTabSheet
      Caption = 'AES Encryption'
      object GroupBox1: TGroupBox
        Left = 3
        Top = 3
        Width = 770
        Height = 529
        Caption = 'AES Encryption/Decryption'
        TabOrder = 0
        object Label1: TLabel
          Left = 16
          Top = 32
          Width = 53
          Height = 15
          Caption = 'Password:'
        end
        object Label2: TLabel
          Left = 16
          Top = 128
          Width = 53
          Height = 15
          Caption = 'Plain Text:'
        end
        object Label3: TLabel
          Left = 16
          Top = 80
          Width = 22
          Height = 15
          Caption = 'Salt:'
        end
        object Label4: TLabel
          Left = 400
          Top = 32
          Width = 34
          Height = 15
          Caption = 'Mode:'
        end
        object EditAESPassword: TEdit
          Left = 88
          Top = 29
          Width = 281
          Height = 23
          PasswordChar = '*'
          TabOrder = 0
          Text = 'MySecretPassword123'
        end
        object EditAESPlainText: TEdit
          Left = 88
          Top = 125
          Width = 281
          Height = 23
          TabOrder = 1
          Text = 'Hello, mORMot2 Cryptography!'
        end
        object ButtonAESEncrypt: TButton
          Left = 400
          Top = 125
          Width = 75
          Height = 25
          Caption = 'Encrypt'
          TabOrder = 2
          OnClick = ButtonAESEncryptClick
        end
        object ButtonAESDecrypt: TButton
          Left = 488
          Top = 125
          Width = 75
          Height = 25
          Caption = 'Decrypt'
          TabOrder = 3
          OnClick = ButtonAESDecryptClick
        end
        object ButtonAESGenerateSalt: TButton
          Left = 400
          Top = 77
          Width = 100
          Height = 25
          Caption = 'Generate Salt'
          TabOrder = 4
          OnClick = ButtonAESGenerateSaltClick
        end
        object MemoAESResult: TMemo
          Left = 16
          Top = 192
          Width = 737
          Height = 321
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -11
          Font.Name = 'Courier New'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 5
        end
        object EditAESSalt: TEdit
          Left = 88
          Top = 77
          Width = 281
          Height = 23
          TabOrder = 6
          Text = 'mormot_demo_fixed_salt_2024'
        end
        object ComboAESMode: TComboBox
          Left = 448
          Top = 29
          Width = 137
          Height = 23
          Style = csDropDownList
          TabOrder = 7
          OnChange = ComboAESModeChange
        end
        object CheckBoxAESRandomIV: TCheckBox
          Left = 88
          Top = 160
          Width = 113
          Height = 17
          Caption = 'Use Random IV'
          Checked = True
          State = cbChecked
          TabOrder = 8
        end
      end
    end
    object TabHash: TTabSheet
      Caption = 'Hash Functions'
      ImageIndex = 1
      object GroupBox2: TGroupBox
        Left = 3
        Top = 3
        Width = 770
        Height = 529
        Caption = 'Hash Calculation'
        TabOrder = 0
        object Label6: TLabel
          Left = 16
          Top = 32
          Width = 55
          Height = 15
          Caption = 'Input Text:'
        end
        object Label7: TLabel
          Left = 16
          Top = 80
          Width = 57
          Height = 15
          Caption = 'Algorithm:'
        end
        object EditHashInput: TEdit
          Left = 88
          Top = 29
          Width = 281
          Height = 23
          TabOrder = 0
          Text = 'Hello, mORMot2!'
        end
        object ComboHashAlgorithm: TComboBox
          Left = 88
          Top = 77
          Width = 137
          Height = 23
          Style = csDropDownList
          TabOrder = 1
          OnChange = ComboHashAlgorithmChange
        end
        object ButtonHashCalculate: TButton
          Left = 400
          Top = 29
          Width = 75
          Height = 25
          Caption = 'Calculate'
          TabOrder = 2
          OnClick = ButtonHashCalculateClick
        end
        object ButtonHashFile: TButton
          Left = 488
          Top = 29
          Width = 75
          Height = 25
          Caption = 'Hash File'
          TabOrder = 3
          OnClick = ButtonHashFileClick
        end
        object MemoHashResult: TMemo
          Left = 16
          Top = 128
          Width = 737
          Height = 385
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -11
          Font.Name = 'Courier New'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 4
        end
      end
    end
    object TabHMAC: TTabSheet
      Caption = 'HMAC Authentication'
      ImageIndex = 2
      object GroupBox3: TGroupBox
        Left = 3
        Top = 3
        Width = 770
        Height = 529
        Caption = 'HMAC Calculation & Verification'
        TabOrder = 0
        object Label8: TLabel
          Left = 16
          Top = 32
          Width = 49
          Height = 15
          Caption = 'Message:'
        end
        object Label9: TLabel
          Left = 16
          Top = 80
          Width = 22
          Height = 15
          Caption = 'Key:'
        end
        object Label10: TLabel
          Left = 16
          Top = 128
          Width = 89
          Height = 15
          Caption = 'Expected HMAC:'
        end
        object EditHMACMessage: TEdit
          Left = 88
          Top = 29
          Width = 281
          Height = 23
          TabOrder = 0
          Text = 'Hello, mORMot2!'
        end
        object EditHMACKey: TEdit
          Left = 88
          Top = 77
          Width = 281
          Height = 23
          TabOrder = 1
          Text = 'secret_key_123'
        end
        object ButtonHMACCalculate: TButton
          Left = 400
          Top = 29
          Width = 75
          Height = 25
          Caption = 'Calculate'
          TabOrder = 2
          OnClick = ButtonHMACCalculateClick
        end
        object ButtonHMACGenerateKey: TButton
          Left = 400
          Top = 77
          Width = 100
          Height = 25
          Caption = 'Generate Key'
          TabOrder = 3
          OnClick = ButtonHMACGenerateKeyClick
        end
        object ButtonHMACVerify: TButton
          Left = 400
          Top = 125
          Width = 75
          Height = 25
          Caption = 'Verify'
          TabOrder = 4
          OnClick = ButtonHMACVerifyClick
        end
        object MemoHMACResult: TMemo
          Left = 16
          Top = 176
          Width = 737
          Height = 337
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -11
          Font.Name = 'Courier New'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 5
        end
        object EditHMACExpected: TEdit
          Left = 128
          Top = 125
          Width = 241
          Height = 23
          TabOrder = 6
        end
      end
    end
    object TabPBKDF2: TTabSheet
      Caption = 'PBKDF2 Key Derivation'
      ImageIndex = 3
      object GroupBox4: TGroupBox
        Left = 3
        Top = 3
        Width = 770
        Height = 529
        Caption = 'PBKDF2 Password-Based Key Derivation'
        TabOrder = 0
        object Label11: TLabel
          Left = 16
          Top = 32
          Width = 53
          Height = 15
          Caption = 'Password:'
        end
        object Label12: TLabel
          Left = 16
          Top = 80
          Width = 22
          Height = 15
          Caption = 'Salt:'
        end
        object Label13: TLabel
          Left = 16
          Top = 128
          Width = 52
          Height = 15
          Caption = 'Iterations:'
        end
        object Label14: TLabel
          Left = 200
          Top = 128
          Width = 62
          Height = 15
          Caption = 'Key Length:'
        end
        object EditPBKDF2Password: TEdit
          Left = 88
          Top = 29
          Width = 281
          Height = 23
          PasswordChar = '*'
          TabOrder = 0
          Text = 'MyPassword123'
        end
        object EditPBKDF2Salt: TEdit
          Left = 88
          Top = 77
          Width = 281
          Height = 23
          TabOrder = 1
          Text = 'random_salt_16_bytes'
        end
        object EditPBKDF2Iterations: TEdit
          Left = 88
          Top = 125
          Width = 89
          Height = 23
          TabOrder = 2
          Text = '100000'
        end
        object EditPBKDF2KeyLength: TEdit
          Left = 280
          Top = 125
          Width = 89
          Height = 23
          TabOrder = 3
          Text = '32'
        end
        object ButtonPBKDF2Derive: TButton
          Left = 400
          Top = 29
          Width = 75
          Height = 25
          Caption = 'Derive Key'
          TabOrder = 4
          OnClick = ButtonPBKDF2DeriveClick
        end
        object ButtonPBKDF2GenerateSalt: TButton
          Left = 400
          Top = 77
          Width = 100
          Height = 25
          Caption = 'Generate Salt'
          TabOrder = 5
          OnClick = ButtonPBKDF2GenerateSaltClick
        end
        object ButtonPBKDF2Verify: TButton
          Left = 400
          Top = 125
          Width = 75
          Height = 25
          Caption = 'Verify'
          TabOrder = 6
          OnClick = ButtonPBKDF2VerifyClick
        end
        object MemoPBKDF2Result: TMemo
          Left = 16
          Top = 176
          Width = 737
          Height = 337
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -11
          Font.Name = 'Courier New'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 7
        end
      end
    end
    object TabRandom: TTabSheet
      Caption = 'Random Generation'
      ImageIndex = 4
      object GroupBox5: TGroupBox
        Left = 3
        Top = 3
        Width = 770
        Height = 529
        Caption = 'Cryptographically Secure Random Generation'
        TabOrder = 0
        object Label15: TLabel
          Left = 16
          Top = 32
          Width = 40
          Height = 15
          Caption = 'Length:'
        end
        object Label16: TLabel
          Left = 16
          Top = 80
          Width = 28
          Height = 15
          Caption = 'Type:'
        end
        object EditRandomLength: TEdit
          Left = 88
          Top = 29
          Width = 89
          Height = 23
          TabOrder = 0
          Text = '32'
        end
        object ComboRandomType: TComboBox
          Left = 88
          Top = 77
          Width = 137
          Height = 23
          Style = csDropDownList
          TabOrder = 1
          OnChange = ComboRandomTypeChange
        end
        object ButtonRandomGenerate: TButton
          Left = 280
          Top = 29
          Width = 75
          Height = 25
          Caption = 'Generate'
          TabOrder = 2
          OnClick = ButtonRandomGenerateClick
        end
        object ButtonRandomPassword: TButton
          Left = 368
          Top = 29
          Width = 75
          Height = 25
          Caption = 'Password'
          TabOrder = 3
          OnClick = ButtonRandomPasswordClick
        end
        object ButtonRandomUUID: TButton
          Left = 456
          Top = 29
          Width = 75
          Height = 25
          Caption = 'UUID'
          TabOrder = 4
          OnClick = ButtonRandomUUIDClick
        end
        object ButtonRandomTest: TButton
          Left = 280
          Top = 77
          Width = 100
          Height = 25
          Caption = 'Test Quality'
          TabOrder = 5
          OnClick = ButtonRandomTestClick
        end
        object MemoRandomResult: TMemo
          Left = 16
          Top = 128
          Width = 737
          Height = 385
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -11
          Font.Name = 'Courier New'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 6
        end
      end
    end
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 581
    Width = 800
    Height = 19
    Panels = <>
    SimplePanel = True
    SimpleText = 'Ready'
  end
  object mORMotAES1: TmORMotAES
    Salt = 'mormot_demo_fixed_salt_2024'
    OnEncryptionComplete = mORMotAES1EncryptionComplete
    OnDecryptionComplete = mORMotAES1DecryptionComplete
    OnError = mORMotAES1Error
    Left = 144
    Top = 328
  end
  object mORMotHash1: TmORMotHash
    OnHashComplete = mORMotHash1HashComplete
    OnError = mORMotHash1Error
    Left = 248
    Top = 264
  end
  object mORMotHMAC1: TmORMotHMAC
    OnHMACComplete = mORMotHMAC1HMACComplete
    OnError = mORMotHMAC1Error
    Left = 480
    Top = 264
  end
  object mORMotPBKDF21: TmORMotPBKDF2
    OnKeyDerivationComplete = mORMotPBKDF21KeyDerivationComplete
    OnError = mORMotPBKDF21Error
    Left = 144
    Top = 264
  end
  object mORMotRandom1: TmORMotRandom
    OnRandomGenerated = mORMotRandom1RandomGenerated
    OnError = mORMotRandom1Error
    Left = 360
    Top = 264
  end
  object OpenDialog1: TOpenDialog
    Left = 664
    Top = 104
  end
end
