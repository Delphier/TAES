unit Prism.Crypto.AES;

interface

uses
  System.SysUtils, Prism.Crypto.AES.Cipher;

type
  TPaddingMode = (pmZeroPadding, pmANSIX923, pmISO10126, pmISO7816, pmPKCS7, pmRandomPadding);

  TAES = class
  private
    class procedure BytePadding(var Data: TBytes; BlockSize: Integer; PaddingMode: TPaddingMode);
  public
    class function Encrypt(const Data, Key: TBytes; KeySize: Integer; const InitVector: TBytes; CipherMode: TCipherMode; PaddingMode: TPaddingMode): TBytes;
    class function EncryptCBC(const Data, Key: TBytes; const KeySize: Integer; const PaddingMode: TPaddingMode = pmPKCS7): TBytes;
    class function Decrypt(const Crypt, Key: TBytes; KeySize: Integer; const InitVector: TBytes; CipherMode: TCipherMode; PaddingMode: TPaddingMode): TBytes;
    class function DecryptCBC(const Crypt, Key: TBytes; const KeySize: Integer; const PaddingMode: TPaddingMode = pmPKCS7): TBytes;
  end;

implementation

class function TAES.Encrypt(const Data, Key: TBytes; KeySize: Integer; const InitVector: TBytes; CipherMode: TCipherMode; PaddingMode: TPaddingMode): TBytes;
var
  Cipher: TAESCipher;
begin
  Cipher := TAESCipher.Create;
  try
    Cipher.Init(Key[0], KeySize, @InitVector[0]);
    Result := Copy(Data, 0, Length(Data));
    if CipherMode in [cmCBC, cmECB] then
      BytePadding(Result, Cipher.BlockSize, PaddingMode);
    Cipher.CipherMode := CipherMode;
    Cipher.Encrypt(Result[0], Result[0], Length(Result));
  finally
    Cipher.Free;
  end;
end;

class function TAES.EncryptCBC(const Data, Key: TBytes; const KeySize: Integer; const PaddingMode: TPaddingMode): TBytes;
var
  Guid: TGUID;
  IV: TBytes;
begin
  CreateGuid(Guid);
  IV := Guid.ToByteArray;
  Result := Encrypt(IV + Data, Key, KeySize, IV, cmCBC, PaddingMode);
end;

class function TAES.Decrypt(const Crypt, Key: TBytes; KeySize: Integer; const InitVector: TBytes; CipherMode: TCipherMode; PaddingMode: TPaddingMode): TBytes;
var
  Cipher: TAESCipher;
  I: Integer;
begin
  Cipher := TAESCipher.Create;
  try
    Cipher.Init(Key[0], KeySize, @InitVector[0]);
    Result := Copy(Crypt, 0, Length(Crypt));
    Cipher.CipherMode := CipherMode;
    Cipher.Decrypt(Result[0], Result[0], Length(Result));
    // Correct the length of Data, based on the used PaddingMode (only for Block based algorithms)
    if CipherMode in [cmCBC, cmECB] then
      case PaddingMode of
        pmANSIX923, pmISO10126, pmPKCS7: // these modes store the original Padding count in the last byte
          SetLength(Result, Length(Result) - Result[Length(Result)-1]);
        pmISO7816: // this mode uses a fixed end-marker. Find it and correct length accordingly.
          for I := Length(Result)-1 downto 0 do
            if Result[I] = $80 then
            begin
              SetLength(Result, I);
              Break;
            end;
      end;
  finally
    Cipher.Free;
  end;
end;

class function TAES.DecryptCBC(const Crypt, Key: TBytes; const KeySize: Integer; const PaddingMode: TPaddingMode): TBytes;
var
  Guid: TGUID;
  IV: TBytes;
begin
  CreateGuid(Guid);
  IV := Guid.ToByteArray;
  Result := Decrypt(Crypt, Key, KeySize, IV, cmCBC, PaddingMode);
  Result := Copy(Result, Length(IV), Length(Result) - Length(IV));
end;

class procedure TAES.BytePadding(var Data: TBytes; BlockSize: Integer; PaddingMode: TPaddingMode);
// Supports: ANSI X.923, ISO 10126, ISO 7816, PKCS7, zero padding and random padding
var
  I, DataBlocks, DataLength, PaddingStart, PaddingCount: Integer;
begin
  BlockSize := BlockSize div 8; // convert bits to bytes
  // Zero and Random padding do not use end-markers, so if Length(Data) is a multiple of BlockSize, no padding is needed
  if PaddingMode in [pmZeroPadding, pmRandomPadding] then
    if Length(Data) mod BlockSize = 0 then
      Exit;
  DataBlocks := (Length(Data) div BlockSize) + 1;
  DataLength := DataBlocks * BlockSize;
  PaddingCount := DataLength - Length(Data);
  // ANSIX923, ISO10126 and PKCS7 store the padding length in a 1 byte end-marker, so any padding length > $FF is not supported
  if PaddingMode in [pmANSIX923, pmISO10126, pmPKCS7] then
    if PaddingCount > $FF then
      Exit;
  PaddingStart := Length(Data);
  SetLength(Data, DataLength);
  case PaddingMode of
    pmZeroPadding, pmANSIX923, pmISO7816: // fill with $00 bytes
      FillChar(Data[PaddingStart], PaddingCount, 0);
    pmPKCS7: // fill with PaddingCount bytes
      FillChar(Data[PaddingStart], PaddingCount, PaddingCount);
    pmRandomPadding, pmISO10126: // fill with random bytes
      for I := PaddingStart to DataLength - 1 do
        Data[I] := Random($FF);
  end;
  case PaddingMode of
    pmANSIX923, pmISO10126:
      Data[DataLength - 1] := PaddingCount;
      // set end-marker with number of bytes added
    pmISO7816:
      Data[PaddingStart] := $80; // set fixed end-markder $80
  end;
end;

end.
