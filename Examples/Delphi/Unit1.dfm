object Form1: TForm1
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = 'AES Encryption'
  ClientHeight = 321
  ClientWidth = 233
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Memo1: TMemo
    Left = 8
    Top = 16
    Width = 217
    Height = 264
    TabOrder = 0
  end
  object BtnEncrypt: TButton
    Left = 8
    Top = 289
    Width = 217
    Height = 25
    Caption = 'Encrypt: CBC-256-PKCS7'
    TabOrder = 1
    OnClick = BtnEncryptClick
  end
end
