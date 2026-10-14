object Form1: TForm1
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = 'AES Encryption and Decryption: CBC/256/PKCS7'
  ClientHeight = 413
  ClientWidth = 567
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OnCreate = FormCreate
  TextHeight = 13
  object Bevel1: TBevel
    Left = 16
    Top = 119
    Width = 535
    Height = 9
    Shape = bsTopLine
  end
  object Label1: TLabel
    Left = 16
    Top = 15
    Width = 105
    Height = 13
    Caption = 'Key (256bit, 32bytes)'
  end
  object Label2: TLabel
    Left = 16
    Top = 61
    Width = 60
    Height = 13
    Caption = 'IV (16bytes)'
  end
  object MemoPlain: TMemo
    Left = 16
    Top = 136
    Width = 217
    Height = 264
    TabOrder = 0
  end
  object BtnEncrypt: TButton
    Left = 239
    Top = 134
    Width = 89
    Height = 25
    Caption = 'Encrypt ->'
    TabOrder = 1
    OnClick = BtnEncryptClick
  end
  object MemoCipher: TMemo
    Left = 334
    Top = 136
    Width = 217
    Height = 264
    TabOrder = 2
  end
  object BtnDecrypt: TButton
    Left = 239
    Top = 165
    Width = 89
    Height = 25
    Caption = '<- Decrypt'
    TabOrder = 3
    OnClick = BtnDecryptClick
  end
  object EditKey: TEdit
    Left = 16
    Top = 31
    Width = 535
    Height = 21
    TabOrder = 4
  end
  object EditIV: TEdit
    Left = 16
    Top = 80
    Width = 535
    Height = 21
    TabOrder = 5
  end
end
