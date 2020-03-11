# TAES
Delphi AES Encryption, Golang AES Decryption. AES-256-CBC-PKCS7...

## Requirements
**DCPCrypt** - https://github.com/StephenGenusa/DCPCrypt

You should Add `DCPCrypt/`, `DCPCrypt/Ciphers` to library search path.

## Example

**Encrypt with Delphi:**
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

**Decrypt with Golang:**
```go
package main

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