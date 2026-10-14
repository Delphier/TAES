unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls;

type
  TForm1 = class(TForm)
    MemoPlain: TMemo;
    BtnEncrypt: TButton;
    MemoCipher: TMemo;
    BtnDecrypt: TButton;
    EditKey: TEdit;
    EditIV: TEdit;
    Bevel1: TBevel;
    Label1: TLabel;
    Label2: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure BtnEncryptClick(Sender: TObject);
    procedure BtnDecryptClick(Sender: TObject);
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

procedure TForm1.FormCreate(Sender: TObject);
begin
  EditKey.Text := 'Key1234567890-1234567890-1234567';
  EditIV.Text := '1234567890123456';
  MemoPlain.Text := 'This is the original text';
  // Encrypted: L/5zwPlqWDSWPy6LbQASgmZF2/cD33ecs/hHeDTUSu0=
end;

procedure TForm1.BtnEncryptClick(Sender: TObject);
begin
  var PlainBytes := TEncoding.UTF8.GetBytes(MemoPlain.Text);
  var Key := TEncoding.UTF8.GetBytes(EditKey.Text); // 256 bits-32 bytes
  var IV := TEncoding.UTF8.GetBytes(EditIV.Text); // 16 bytes

  var CipherBytes := TAES.Encrypt(PlainBytes, Key, 256, IV, cmCBC, pmPKCS7);
  MemoCipher.Text := TNetEncoding.Base64.EncodeBytesToString(CipherBytes);
end;

procedure TForm1.BtnDecryptClick(Sender: TObject);
begin
  var Key := TEncoding.UTF8.GetBytes(EditKey.Text); // 256 bits-32 bytes
  var IV := TEncoding.UTF8.GetBytes(EditIV.Text); // 16 bytes

  var CiphierBytes := TNetEncoding.Base64.DecodeStringToBytes(MemoCipher.Text);
  var PlainBytes := TAES.Decrypt(CiphierBytes, Key, 256, IV, cmCBC, pmPKCS7);
  MemoPlain.Text := TEncoding.UTF8.GetString(PlainBytes);
end;

end.
