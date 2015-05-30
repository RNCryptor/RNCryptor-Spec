## Specification for RNCryptor data format version 2

**Note: The v2 format truncates multibyte (e.g. Chinese) passwords. This was a bug in the Objective-C version of RNCryptor that was not reproduced in other implementaions. Data encrypted with a multibyte password may not interoperate all implementations.**

    Byte:     |    0    |    1    |      2-9       |  10-17   | 18-33 | <-      ...     -> | n-32 - n |
    Contents: | version | options | encryptionSalt | HMACSalt |  IV   | ... ciphertext ... |   HMAC   |
    

* version (1 byte): Data format version (2)
* options (1 byte): bit 0 - uses password
* encryptionSalt (8 bytes): iff option includes "uses password"
* HMACSalt (8 bytes): iff options includes "uses password"
* IV (16 bytes)
* ciphertext (variable) -- Encrypted in CBC mode
* HMAC (32 bytes)

All data is in network order (big-endian).

Note that the version of the RNCryptor ObjC library is not directly related to the version of the RNCryptor file format. For example, v2.2 of the RNCryptor ObjC library writes v3 of the file format. The versioning of an implementation is related to its API, not the file formats it supports.

### Password-based encryption (abstract language)

```
def Encrypt(Password, Plaintext) =
    assert(password.length > 0)
    EncryptionSalt = RandomDataOfLength(8)
    
    // See note at beginning of specification. This was a bug in the ObjC version.
    // The password is truncated to the number of characters (rather than the number of bytes)
    TruncatedPassword = ByteRange(Password, 0, Characters(Password))

    EncryptionKey = PBKDF2(EncryptionSalt, 32 length, 10k iterations, SHA-1, TruncatedPassword)

    HMACSalt = RandomDataOfLength(8)
    HMACKey = PBKDF2(HMACSalt, 32 length, 10k iterations, SHA-1, TruncatedPassword)

    IV = RandomDataOfLength(16)

    Header = 2 || 1 || EncryptionSalt || HMACSalt || IV
    Ciphertext = AES256(Plaintext, ModeCBC, IV, EncryptionKey)
    HMAC = HMAC(Header || Ciphertext, HMACKey, SHA-256)
    Message = Header || Ciphertext || HMAC
    return Message
```

1. Password must be non-empty
1. Generate a random encryption salt
1. (Incorrectly) truncate the password. Count the number of characters and use that many bytes.
1. Generate the encryption key using PBKDF2 (see your language docs for how to call this). Pass the password as a string, the random encryption salt, 10,000 iterations, and SHA-1 PRF. Request a length of 32 bytes.
1. Generate a random HMAC salt
1. Generate the HMAC key using PBKDF2 (see your language docs for how to call this). Pass the password as a string, the random HMAC salt, 10,000 iterations, and SHA-1 PRF. Request a length of 32 bytes.
1. Generate a random IV
1. Encrypt the data using the encryption key (above), the IV (above), AES-256, and the CBC mode. This is the default mode for almost all AES encryption libraries.
1. Pass your header and ciphertext to an HMAC function, along with the HMAC key (above), and the PRF "SHA-256" (see your library's docs for what the names of the PRF functions are; this might also be called "SHA-2, 256-bits").
1. Put these elements together in the format given.

Note: The RNCryptor format v3 uses SHA-1 for PBKDF2, but SHA-256 for HMAC.

### Key-based encryption (abstract language)

```
def Encrypt(EncryptionKey[32], HMACKey[32], Plaintext) =
    IV = RandomDataOfLength(8)        
    Header = 3 || 0 || IV
    Ciphertext = AES256(plaintext, ModeCBC, IV, EncryptionKey)
    HMAC = HMAC(Header || Ciphertext, HMACKey, SHA-256)
    Message = Header || Ciphertext || HMAC
    return Message
```

1. Generate a random IV
1. Encrypt the data using the encryption key, the IV, AES-256, and the CBC mode. This is the default mode for almost all AES encryption libraries.
1. Pass your header and ciphertext to an HMAC function, along with the HMAC key (above), and the PRF "SHA-256" (see your library's docs for what the names of the PRF functions are; this might also be called "SHA-2, 256-bits").
1. Put these elements together in the format given.

### Password-based decryption (abstract language)

```
def Decrypt(Password, Message) =
    (Version,Options,EncryptionSalt,HMACSalt,IV,Ciphertext,HMAC) = Split(Message)

    // See note at beginning of specification. This was a bug in the ObjC version.
    // The password is truncated to the number of characters (rather than the number of bytes)
    TruncatedPassword = ByteRange(Password, 0, Characters(Password))

    EncryptionKey = PKBDF2(EncryptionSalt, 32 length, 10k iterations, TruncatedPassword)
    HMACKey = PKBDF2(HMACSalt, 32 length, 10k iterations, TruncatedPassword)

    Header = 2 || 1 || EncryptionSalt || HMACSalt || IV
    Plaintext = AES256Decrypt(Ciphertext, ModeCBC, IV, EncryptionKey)
    ComputedHMAC = HMAC(Header || Ciphertext, HMACKey, SHA-256)
    if ConsistentTimeEqual(ComputedHMAC, HMAC) return Plaintext else return Error
```

1. Pull apart the pieces as described in the data format.
1. (Incorrectly) truncate the password. Count the number of characters and use that many bytes.
1. Generate the encryption key using PBKDF2 (see your language docs for how to call this). Pass the password as a string, the random encryption salt, 10,000 iterations, and SHA-1 PRF. Request a length of 32 bytes.
1. Generate the HMAC key using PBKDF2 (see your language docs for how to call this). Pass the password as a string, the random HMAC salt, 10,000 iterations, and SHA-1 PRF. Request a length of 32 bytes.
1. Decrypt the data using the encryption key (above), the given IV, AES-256, and the CBC mode. This is the default mode for almost all AES encryption libraries.
1. Pass your header and ciphertext to an HMAC function, along with the HMAC key (above), and the PRF "SHA-256" (see your library's docs for what the names of the PRF functions are; this might also be called "SHA-2, 256-bits").
1. Compare the computed HMAC with the expected HMAC using a constant time equality function (see below). If they are equal, return the plaintext. Otherwise, return an error

Note: The RNCryptor format v3 uses SHA-1 for PBKDF2, but SHA-256 for HMAC.

### Consistent-time equality checking

When comparing the computed HMAC with the expected HMAC, it is important that your comparison be made in consistent time. Your comparison function should compare all of the bytes of the ExpectedHMAC, even if it finds a mismatch. Otherwise, your comparison can be subject to a timing attack, where the attacker sends you different HMACs and times how long it takes you to return that they are not equal. Using this, the attacker can progressively determine each byte of the HMAC.

Here is an example consistent-time equality function in ObjC:
``` objc
- (BOOL)rnc_isEqualInConsistentTime:(NSData *)otherData {
  // The point of this routine is XOR the bytes of each data and accumulate the results with OR.
  // If any bytes are different, then the OR will accumulate some non-0 value.
  uint8_t result = otherData.length - self.length;  // Start with 0 (equal) only if our lengths are equal

  const uint8_t *myBytes = [self bytes];
  const NSUInteger myLength = [self length];
  const uint8_t *otherBytes = [otherData bytes];
  const NSUInteger otherLength = [otherData length];

  for (NSUInteger i = 0; i < otherLength; ++i) {
    // Use mod to wrap around ourselves if they are longer than we are.
    // Remember, we already broke equality if our lengths are different.
    result |= myBytes[i % myLength] ^ otherBytes[i];
  }

  return result == 0;
}
```

## Changes since version 2

The version 3 format is identical to the version 2 format except that in the version 2 format, PBKDF2 was run on an accidentally truncated version of the password. The length of the password passed to the PBKDF2 function was the number of characters in the password, not the number of bytes. So multi-byte passwords were truncated.