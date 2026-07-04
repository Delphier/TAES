# TAES

A lightweight AES encryption/decryption unit for Delphi.

## Features

- **AES only** this library is focused exclusively on the AES algorithm; it does not implement other ciphers.
- **Single unit, no external dependencies** easy to drop into any Delphi project.
- **Multiple chaining modes** CBC, CFB (8-bit and full block), OFB, CTR, and ECB.
- **Multiple padding modes** PKCS7, ANSI X.923, ISO 10126, ISO 7816, zero padding, and random padding.
- **128 / 192 / 256-bit keys** supports all standard AES key sizes.

## Installation

Copy `Prism.Crypto.AES.pas` (and its dependency `Prism.Crypto.AES.Cipher.pas`) into your project, then add the unit to your uses clause:

```delphi
uses
  Prism.Crypto.AES;
```

## Examples

Encrypt with Delphi:
```delphi
uses
  Prism.Crypto.AES, System.NetEncoding;

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
```

Decrypt with Golang:
```go
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"log"
)

func main() {
	encryptedText := "L/5zwPlqWDSWPy6LbQASgmZF2/cD33ecs/hHeDTUSu0="
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		log.Fatal(err)
	}
	key := []byte("Key1234567890-1234567890-1234567")
	iv := []byte("1234567890123456")
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(data, data)
	data, err = pkcs7strip(data, aes.BlockSize)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data))
	// Output: This is the original text
}
```

## Acknowledgments

Most of the original cipher implementation in this library is derived from DCPcrypt (the DCPcrypt Cryptographic Component Library), originally written by David Barton. Many thanks to the DCPcrypt project and its author for the underlying work.
