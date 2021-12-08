// Code Owner: https://stackoverflow.com/a/43591761
// Clue from: https://github.com/halilhanbadem/AES-256-CBCEncryptionDelphi_PHP

unit Prism.Crypto.AES;

interface

uses
  SysUtils;

type
  TChainingMode = (cmCBC, cmCFB8bit, cmCFBblock, cmOFB, cmCTR, cmECB);
  TPaddingMode = (pmZeroPadding, pmANSIX923, pmISO10126, pmISO7816, pmPKCS7, pmRandomPadding);

  TAES = class
  private
    class procedure BytePadding(var Data: TBytes; BlockSize: integer; PaddingMode: TPaddingMode);
  public
    class function Encrypt(const Data: TBytes; const Key: TBytes; KeySize: integer; const InitVector: TBytes; ChainingMode: TChainingMode; PaddingMode: TPaddingMode): TBytes;
    class function EncryptCBC(const AData, AKey: TBytes; const AKeySize: Integer; const APaddingMode: TPaddingMode = pmPKCS7): TBytes;
    class function Decrypt(const Crypt: TBytes; const Key: TBytes; KeySize: integer; const InitVector: TBytes; ChainingMode: TChainingMode; PaddingMode: TPaddingMode): TBytes;
    class function DecryptCBC(const ACrypt, AKey: TBytes; const AKeySize: Integer; const APaddingMode: TPaddingMode = pmPKCS7): TBytes;
  end;

implementation

uses
  DCPrijndael;

class function TAES.Encrypt(const Data: TBytes; const Key: TBytes; KeySize: integer; const InitVector: TBytes; ChainingMode: TChainingMode; PaddingMode: TPaddingMode): TBytes;
var
  Cipher: TDCP_rijndael;
begin
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key[0], KeySize, @InitVector[0]);
    // Copy Data => Crypt
    Result := Copy(Data, 0, Length(Data));
    // Padd Crypt to required length (for Block based algorithms)
    if ChainingMode in [cmCBC, cmECB] then
      BytePadding(Result, Cipher.BlockSize, PaddingMode);
    // Encrypt Crypt using the algorithm specified in ChainingMode
    case ChainingMode of
      cmCBC:
        Cipher.EncryptCBC(Result[0], Result[0], Length(Result));
      cmCFB8bit:
        Cipher.EncryptCFB8bit(Result[0], Result[0], Length(Result));
      cmCFBblock:
        Cipher.EncryptCFBblock(Result[0], Result[0], Length(Result));
      cmOFB:
        Cipher.EncryptOFB(Result[0], Result[0], Length(Result));
      cmCTR:
        Cipher.EncryptCTR(Result[0], Result[0], Length(Result));
      cmECB:
        Cipher.EncryptECB(Result[0], Result[0]);
    end;
  finally
    Cipher.Free;
  end;
end;

class function TAES.EncryptCBC(const AData, AKey: TBytes; const AKeySize: Integer; const APaddingMode: TPaddingMode): TBytes;
var
  Guid: TGUID;
  IV: TBytes;
begin
  CreateGuid(Guid);
  IV := Guid.ToByteArray;
  Result := Encrypt(IV + AData, AKey, AKeySize, IV, cmCBC, APaddingMode);
end;

class function TAES.Decrypt(const Crypt: TBytes; const Key: TBytes; KeySize: integer; const InitVector: TBytes; ChainingMode: TChainingMode; PaddingMode: TPaddingMode): TBytes;
var
  Cipher: TDCP_rijndael;
  I: integer;
begin
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key[0], KeySize, @InitVector[0]);
    // Copy Crypt => Data
    Result := Copy(Crypt, 0, Length(Crypt));
    // Decrypt Data using the algorithm specified in ChainingMode
    case ChainingMode of
      cmCBC: Cipher.DecryptCBC(Result[0], Result[0], Length(Result));
      cmCFB8bit: Cipher.DecryptCFB8bit(Result[0], Result[0], Length(Result));
      cmCFBblock: Cipher.DecryptCFBblock(Result[0], Result[0], Length(Result));
      cmOFB: Cipher.DecryptOFB(Result[0], Result[0], Length(Result));
      cmCTR: Cipher.DecryptCTR(Result[0], Result[0], Length(Result));
      cmECB: Cipher.DecryptECB(Result[0], Result[0]);
    end;
    // Correct the length of Data, based on the used PaddingMode (only for Block based algorithms)
    if ChainingMode in [cmCBC, cmECB] then
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

class function TAES.DecryptCBC(const ACrypt, AKey: TBytes; const AKeySize: Integer; const APaddingMode: TPaddingMode): TBytes;
var
  Guid: TGUID;
  IV: TBytes;
begin
  CreateGuid(Guid);
  IV := Guid.ToByteArray;
  Result := Decrypt(ACrypt, AKey, AKeySize, IV, cmCBC, APaddingMode);
  Result := Copy(Result, Length(IV), Length(Result) - Length(IV));
end;

class procedure TAES.BytePadding(var Data: TBytes; BlockSize: integer; PaddingMode: TPaddingMode);
// Supports: ANSI X.923, ISO 10126, ISO 7816, PKCS7, zero padding and random padding
var
  I, DataBlocks, DataLength, PaddingStart, PaddingCount: integer;
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
