object NicSelectDialog: TNicSelectDialog
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Select Network Interface'
  ClientHeight = 320
  ClientWidth = 500
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poOwnerFormCenter
  OnShow = FormShow
  TextHeight = 13
  object LabelPrompt: TLabel
    Left = 12
    Top = 12
    Width = 476
    Height = 13
    Caption = 'Select the network interface to use as the multicast source address:'
  end
  object ListBoxNics: TListBox
    Left = 12
    Top = 32
    Width = 476
    Height = 238
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ItemHeight = 16
    ParentFont = False
    TabOrder = 0
    OnClick = ListBoxNicsClick
  end
  object PanelButtons: TPanel
    Left = 0
    Top = 282
    Width = 500
    Height = 38
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 1
    object ButtonOk: TButton
      Left = 332
      Top = 6
      Width = 75
      Height = 25
      Caption = 'OK'
      Default = True
      Enabled = False
      ModalResult = 1
      TabOrder = 0
      OnClick = ButtonOkClick
    end
    object ButtonCancel: TButton
      Left = 413
      Top = 6
      Width = 75
      Height = 25
      Cancel = True
      Caption = 'Cancel'
      ModalResult = 2
      TabOrder = 1
      OnClick = ButtonCancelClick
    end
  end
end
