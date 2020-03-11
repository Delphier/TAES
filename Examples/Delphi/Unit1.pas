unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TForm1 = class(TForm)
    Memo1: TMemo;
    BtnEncrypt: TButton;
    procedure BtnEncryptClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

uses
  Prism.Crypto.AES, System.NetEncoding;

{$R *.dfm}

procedure TForm1.BtnEncryptClick(Sender: TObject);
var
  OriginalText, Key, IV, EncryptedText: TBytes;
begin
  OriginalText := TEncoding.ANSI.GetBytes('This is the original text');
  Key := TEncoding.ANSI.GetBytes('Key1234567890-1234567890-1234567'); // 256 bits-32 bytes
  IV := TEncoding.ANSI.GetBytes('1234567890123456'); // 16 bytes

  EncryptedText := TAES.Encrypt(OriginalText, Key, 256, IV, cmCBC, pmPKCS7);
  Memo1.Text := TNetEncoding.Base64.EncodeBytesToString(EncryptedText);
  // Output: L/5zwPlqWDSWPy6LbQASgmZF2/cD33ecs/hHeDTUSu0=
end;

end.
