# TAES

A lightweight AES encryption/decryption unit for Delphi.

## Features

- **AES only** this library is focused exclusively on the AES algorithm; it does not implement other ciphers.
- **Single unit, no external dependencies** easy to drop into any Delphi project.
- **Multiple chaining modes** CBC, CFB (8-bit and full block), OFB, CTR, and ECB.
- **Multiple padding modes** PKCS7, ANSI X.923, ISO 10126, ISO 7816, zero padding, and random padding.
- **128 / 192 / 256-bit keys** supports all standard AES key sizes.

## Installation

Copy `Prism.Crypto.AES.pas` into your project, then add the unit to your uses clause:

```delphi
uses
  Prism.Crypto.AES;
```
## API Overview

```delphi
type
  TCipherMode = (cmECB, cmCBC, cmCFB8bit, cmCFBblock, cmOFB, cmCTR);
  TPaddingMode = (pmZeroPadding, pmANSIX923, pmISO10126, pmISO7816, pmPKCS7, pmRandomPadding);

  TAES = class
    class function Encrypt(const Data, Key: TBytes; KeySize: Integer; const InitVector: TBytes; CipherMode: TCipherMode; PaddingMode: TPaddingMode): TBytes;
    class function Decrypt(const Crypt, Key: TBytes; KeySize: Integer; const InitVector: TBytes; CipherMode: TCipherMode; PaddingMode: TPaddingMode): TBytes;
    class function EncryptCBC(const Data, Key: TBytes; const KeySize: Integer; const PaddingMode: TPaddingMode = pmPKCS7): TBytes;
    class function DecryptCBC(const Crypt, Key: TBytes; const KeySize: Integer; const PaddingMode: TPaddingMode = pmPKCS7): TBytes;
  end;
```
- `KeySize` is expressed in bits (128, 192, or 256) and must match the length of `Key` in bytes × 8.
- Padding (`PaddingMode`) only applies to block-based chaining modes (`cmCBC`, `cmECB`); stream-style modes (`cmCFB8bit`, `cmCFBblock`, `cmOFB`, `cmCTR`) don't require padding.
- `EncryptCBC` / `DecryptCBC` generate a random 16-byte IV (via `TGUID`), prepend it to the ciphertext on encryption, and strip it back off on decryption — handy when you'd rather not manage the IV yourself. `Encrypt` / `Decrypt` give you full control, including supplying your own IV.

## Example: Encrypt in Delphi, Decrypt in Go

Encrypt with Delphi (AES-256, CBC, PKCS7 padding), then Base64-encode the result:

```delphi
uses
  Prism.Crypto.AES, System.NetEncoding;

procedure TForm1.BtnEncryptClick(Sender: TObject);
var
  OriginalText, Key, IV, EncryptedText: TBytes;
begin
  OriginalText := TEncoding.UTF8.GetBytes('This is the original text');
  Key := TEncoding.UTF8.GetBytes('Key1234567890-1234567890-1234567'); // 256 bits-32 bytes
  IV := TEncoding.UTF8.GetBytes('1234567890123456'); // 16 bytes

  EncryptedText := TAES.Encrypt(OriginalText, Key, 256, IV, cmCBC, pmPKCS7);
  Memo1.Text := TNetEncoding.Base64.EncodeBytesToString(EncryptedText);
  // Output: L/5zwPlqWDSWPy6LbQASgmZF2/cD33ecs/hHeDTUSu0=
end;
```

Decrypt the resulting Base64 string with Go, using only the standard library:

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
Because both sides use the same key, IV, chaining mode, and padding scheme, the two snippets are fully interoperable — decrypting on the Go side recovers the exact original plaintext.

## Acknowledgments

Most of the original cipher implementation in this library is derived from DCPcrypt (the DCPcrypt Cryptographic Component Library), originally written by David Barton. Many thanks to the DCPcrypt project and its author for the underlying work.
