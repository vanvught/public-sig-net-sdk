object K0EntryDialog: TK0EntryDialog
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Sig-Net Root Key (K0) Entry'
  ClientHeight = 578
  ClientWidth = 620
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  TextHeight = 13
  object LabelInstructions: TLabel
    Left = 16
    Top = 16
    Width = 588
    Height = 39
    AutoSize = False
    Caption = 'Instructions will appear here'
    WordWrap = True
  end
  object LabelValidation: TLabel
    Left = 16
    Top = 272
    Width = 588
    Height = 68
    AutoSize = False
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -12
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
    WordWrap = True
  end
  object PanelValidationChecks: TPanel
    Left = 16
    Top = 272
    Width = 588
    Height = 88
    BevelOuter = bvNone
    TabOrder = 9
    object EditCheckLength: TEdit
      Left = 0
      Top = 0
      Width = 588
      Height = 22
      Color = clWindow
      ReadOnly = True
      TabOrder = 0
      Text = 'Length: -'
    end
    object EditCheckClasses: TEdit
      Left = 0
      Top = 22
      Width = 588
      Height = 22
      Color = clWindow
      ReadOnly = True
      TabOrder = 1
      Text = 'Character classes: -'
    end
    object EditCheckIdentical: TEdit
      Left = 0
      Top = 44
      Width = 588
      Height = 22
      Color = clWindow
      ReadOnly = True
      TabOrder = 2
      Text = 'No triple identical characters: -'
    end
    object EditCheckSequential: TEdit
      Left = 0
      Top = 66
      Width = 588
      Height = 22
      Color = clWindow
      ReadOnly = True
      TabOrder = 3
      Text = 'No 4-character sequential run: -'
    end
  end
  object Label1: TLabel
    Left = 16
    Top = 369
    Width = 71
    Height = 13
    Caption = 'K0 (Root Key):'
  end
  object Label2: TLabel
    Left = 16
    Top = 394
    Width = 165
    Height = 13
    Caption = 'Derived Keys (HKDF-Expand):'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label3: TLabel
    Left = 32
    Top = 417
    Width = 59
    Height = 13
    Caption = 'Sender Key:'
  end
  object Label4: TLabel
    Left = 32
    Top = 449
    Width = 57
    Height = 13
    Caption = 'Citizen Key:'
  end
  object Label5: TLabel
    Left = 32
    Top = 481
    Width = 99
    Height = 13
    Caption = 'Manager Global Key:'
  end
  object Label7: TLabel
    Left = 32
    Top = 513
    Width = 94
    Height = 13
    Caption = 'Manager Local Key:'
  end
  object RadioGroupMode: TRadioGroup
    Left = 16
    Top = 64
    Width = 588
    Height = 81
    Caption = ' K0 Entry Method '
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
    TabOrder = 0
    OnClick = RadioGroupModeClick
  end
  object PanelPassphrase: TPanel
    Left = 16
    Top = 152
    Width = 588
    Height = 114
    BevelOuter = bvNone
    TabOrder = 1
    object Label6: TLabel
      Left = 0
      Top = 0
      Width = 109
      Height = 13
      Caption = 'Passphrase (10-64ch):'
    end
    object EditPassphrase: TEdit
      Left = 0
      Top = 20
      Width = 588
      Height = 21
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentFont = False
      TabOrder = 0
      OnChange = EditPassphraseChange
    end
    object ButtonPassphraseToK0: TButton
      Left = 196
      Top = 52
      Width = 180
      Height = 30
      Caption = 'Passphrase to K0'
      TabOrder = 1
      OnClick = ButtonPassphraseToK0Click
    end
    object ButtonGenerateRandomPassphrase: TButton
      Left = 0
      Top = 52
      Width = 180
      Height = 30
      Caption = 'Generate Random Passphase'
      TabOrder = 2
      OnClick = ButtonGenerateRandomPassphraseClick
    end
    object ButtonGenerateRandomK0: TButton
      Left = 392
      Top = 52
      Width = 180
      Height = 30
      Caption = 'Generate Random K0'
      TabOrder = 3
      OnClick = ButtonGenerateRandomK0Click
    end
    object ButtonUseTestK0: TButton
      Left = 392
      Top = 84
      Width = 180
      Height = 30
      Caption = 'Generate Test K0'
      TabOrder = 4
      OnClick = ButtonUseTestK0Click
    end
  end
  object EditK0Display: TEdit
    Left = 96
    Top = 366
    Width = 508
    Height = 22
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    TabOrder = 2
  end
  object EditSenderKey: TEdit
    Left = 144
    Top = 414
    Width = 460
    Height = 22
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    TabOrder = 3
  end
  object EditCitizenKey: TEdit
    Left = 144
    Top = 446
    Width = 460
    Height = 22
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    TabOrder = 4
  end
  object EditManagerGlobalKey: TEdit
    Left = 144
    Top = 478
    Width = 460
    Height = 22
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    TabOrder = 5
  end
  object EditManagerLocalKey: TEdit
    Left = 144
    Top = 510
    Width = 460
    Height = 22
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    TabOrder = 8
  end
  object ButtonOK: TButton
    Left = 448
    Top = 538
    Width = 75
    Height = 25
    Caption = 'OK'
    Default = True
    TabOrder = 6
    OnClick = ButtonOKClick
  end
  object ButtonCancel: TButton
    Left = 529
    Top = 538
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 7
  end
end
