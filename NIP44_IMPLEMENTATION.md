# NIP-44 Encryption Implementation

This implementation adds support for **NIP-44 encrypted messages** alongside the existing **NIP-04** encryption in the Nostr.Client library.

## What is NIP-44?

NIP-44 is an improved encryption standard for Nostr that provides better security than NIP-04. It uses:
- **ChaCha20** stream cipher (instead of AES-256-CBC)
- **HKDF-SHA256** for key derivation (v2 only)
- **HMAC-SHA256** for message authentication
- **Padding** to hide message length (v2 only)

## Versions

### NIP-44 Version 2 (Recommended) ✅
- Uses HKDF for proper key derivation
- Includes padding to hide message length
- More secure MAC calculation (includes nonce)
- **This is the recommended version for new implementations**

### NIP-44 Version 1 (Legacy)
- Simpler key derivation
- No padding (message length can leak)
- Provided for backward compatibility only

### NIP-04 (Original)
- Uses AES-256-CBC encryption
- Still supported for backward compatibility
- **Default for existing code to avoid breaking changes**

## Usage

### Basic Encryption

```csharp
using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.Messages.Direct;

// Generate or load keys
var senderPrivateKey = NostrPrivateKey.GenerateNew();
var recipientPrivateKey = NostrPrivateKey.GenerateNew();
var recipientPublicKey = recipientPrivateKey.DerivePublicKey();

// Create event
var ev = new NostrEvent
{
    Kind = NostrKind.ShortTextNote,
    Content = "Secret message",
    CreatedAt = DateTime.UtcNow
};

// Encrypt using NIP-44 v2 (recommended)
var encrypted = ev.Encrypt(senderPrivateKey, recipientPublicKey, NostrEncryptionType.Nip44V2);

// Decrypt
var decrypted = encrypted.DecryptContent(recipientPrivateKey);
Console.WriteLine(decrypted); // "Secret message"
```

### Direct Messages (Kind 4)

```csharp
// Encrypt as direct message (sets kind to 4)
var encryptedDM = ev.EncryptDirect(senderPrivateKey, recipientPublicKey, NostrEncryptionType.Nip44V2);

// Decrypt works the same way
var decryptedDM = encryptedDM.DecryptContent(recipientPrivateKey);
```

### Encryption Types

```csharp
// NIP-04 (default for backward compatibility)
var nip04 = ev.Encrypt(sender, recipient, NostrEncryptionType.Nip04);

// NIP-44 Version 1 (legacy)
var nip44v1 = ev.Encrypt(sender, recipient, NostrEncryptionType.Nip44V1);

// NIP-44 Version 2 (recommended)
var nip44v2 = ev.Encrypt(sender, recipient, NostrEncryptionType.Nip44V2);
```

### Automatic Detection

The decryption method automatically detects whether a message uses NIP-04 or NIP-44:

```csharp
// Works with both NIP-04 and NIP-44 encrypted messages
var decrypted = encryptedEvent.DecryptContent(privateKey);
```

## API Reference

### NostrEncryptionType Enum

- `Nip04` - Original AES-256-CBC encryption
- `Nip44V1` - ChaCha20 with simple key derivation (legacy)
- `Nip44V2` - ChaCha20 with HKDF, padding, and improved MAC (recommended)

### Extension Methods

#### `NostrEvent.Encrypt()`
Encrypts an event preserving its kind.

```csharp
public static NostrEncryptedEvent Encrypt(
    this NostrEvent ev, 
    NostrPrivateKey sender, 
    NostrPublicKey recipientPubkey, 
    NostrEncryptionType encryptionType = NostrEncryptionType.Nip04)
```

#### `NostrEvent.EncryptDirect()`
Encrypts an event as a direct message (kind 4).

```csharp
public static NostrEncryptedEvent EncryptDirect(
    this NostrEvent ev, 
    NostrPrivateKey sender, 
    NostrPublicKey recipientPubkey, 
    NostrEncryptionType encryptionType = NostrEncryptionType.Nip04)
```

#### `NostrEncryptedEvent.DecryptContent()`
Decrypts the content of an encrypted event. Automatically detects encryption type.

```csharp
public string? DecryptContent(NostrPrivateKey privateKey)
```

### Low-Level API

For direct encryption/decryption without events:

```csharp
using Nostr.Client.Utils;

// Get conversation key (ECDH shared secret)
var sharedKey = privateKey.DeriveSharedKey(publicKey);
var conversationKey = sharedKey.Ec.ToBytes().ToArray();

// Encrypt
var encrypted = NostrEncryptionNip44.Encrypt("plaintext", conversationKey, version: 2);

// Decrypt
var decrypted = NostrEncryptionNip44.Decrypt(encrypted, conversationKey);
```

## Security Considerations

### Why NIP-44 v2 is Better

1. **Proper Key Derivation**: Uses HKDF instead of simple concatenation
2. **Length Hiding**: Padding prevents message length analysis
3. **Better MAC**: Includes nonce in authentication
4. **Modern Cipher**: ChaCha20 is faster and more secure than CBC mode

### Migration from NIP-04

The implementation maintains **backward compatibility**:
- Default encryption type is still `Nip04` to avoid breaking existing code
- Decryption automatically detects the encryption type
- You can gradually migrate by explicitly using `NostrEncryptionType.Nip44V2`

### Recommendations

✅ **DO:**
- Use `NostrEncryptionType.Nip44V2` for all new implementations
- Keep private keys secure and never transmit them
- Verify message authentication (handled automatically)

❌ **DON'T:**
- Use NIP-04 for new implementations (kept for compatibility only)
- Use NIP-44 v1 (use v2 instead)
- Reuse nonces (handled automatically with secure random generation)

## Implementation Details

### File Structure

```
src/Nostr.Client/
├── Utils/
│   ├── NostrEncryption.cs              # NIP-04 (AES-256-CBC)
│   └── NostrEncryptionNip44.cs         # NIP-44 v1 and v2 (ChaCha20)
└── Messages/
    └── Direct/
        ├── NostrEncryptedEvent.cs              # Main encrypted event class
        └── NostrEventEncryptionExtensions.cs   # Extension methods
```

### ChaCha20 Implementation

The implementation includes a pure C# ChaCha20 cipher implementation since .NET's `ChaCha20Poly1305` is an AEAD cipher and NIP-44 requires standalone ChaCha20 with separate HMAC authentication.

### Padding Algorithm (NIP-44 v2)

Messages are padded to the next power of 2 (minimum 32 bytes) to hide the actual message length:
- Messages 1-32 bytes → padded to 32 bytes
- Messages 33-64 bytes → padded to 64 bytes
- Messages 65-128 bytes → padded to 128 bytes
- And so on...

## Testing

Comprehensive tests are included in `test/Nostr.Client.Tests/EncryptedEventTests.cs`:

```bash
# Run all encryption tests
dotnet test --filter "FullyQualifiedName~EncryptedEventTests"
```

Tests cover:
- NIP-04 encryption/decryption
- NIP-44 v1 encryption/decryption
- NIP-44 v2 encryption/decryption
- Long messages
- Unicode/emoji support
- Automatic type detection
- Multiple recipient scenarios

## References

- [NIP-04: Encrypted Direct Messages](https://github.com/nostr-protocol/nips/blob/master/04.md)
- [NIP-44: Encrypted Payloads](https://github.com/nostr-protocol/nips/blob/master/44.md)
- [ChaCha20 Specification](https://tools.ietf.org/html/rfc7539)
- [HKDF Specification](https://tools.ietf.org/html/rfc5869)

