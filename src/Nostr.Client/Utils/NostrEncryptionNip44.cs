using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Nostr.Client.Utils
{
    /// <summary>
    /// NIP-44 encryption utilities (version 1 and 2)
    /// Version 2 is recommended for new implementations
    /// </summary>
    public static class NostrEncryptionNip44
    {
        private const int MinPlaintextSize = 0x0001; // 1 byte
        private const int MaxPlaintextSize = 0xFFFF; // 65535 bytes

        /// <summary>
        /// Encrypt plaintext using NIP-44
        /// </summary>
        /// <param name="plaintext">Text to encrypt</param>
        /// <param name="conversationKey">32-byte shared key derived from ECDH</param>
        /// <param name="version">NIP-44 version (1 or 2, default is 2)</param>
        /// <returns>Base64-encoded encrypted payload with version prefix</returns>
        public static string Encrypt(string plaintext, byte[] conversationKey, int version = 2)
        {
            return version switch
            {
                1 => EncryptV1(plaintext, conversationKey),
                2 => EncryptV2(plaintext, conversationKey),
                _ => throw new ArgumentException("Invalid NIP-44 version. Supported versions: 1, 2", nameof(version))
            };
        }

        /// <summary>
        /// Decrypt NIP-44 encrypted payload
        /// </summary>
        /// <param name="payload">Base64-encoded encrypted payload</param>
        /// <param name="conversationKey">32-byte shared key derived from ECDH</param>
        /// <returns>Decrypted plaintext</returns>
        public static string Decrypt(string payload, byte[] conversationKey)
        {
            var data = Convert.FromBase64String(payload);
            if (data.Length == 0)
                throw new ArgumentException("Empty payload", nameof(payload));

            var version = data[0];

            return version switch
            {
                1 => DecryptV1(data, conversationKey),
                2 => DecryptV2(data, conversationKey),
                _ => throw new ArgumentException($"Unsupported NIP-44 version: {version}", nameof(payload))
            };
        }

        #region Version 2 (Recommended)

        private static string EncryptV2(string plaintext, byte[] conversationKey)
        {
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            if (plaintextBytes.Length < MinPlaintextSize || plaintextBytes.Length > MaxPlaintextSize)
                throw new ArgumentException($"Plaintext size must be between {MinPlaintextSize} and {MaxPlaintextSize} bytes", nameof(plaintext));

            // Generate random nonce
            var nonce = new byte[32];
            RandomNumberGenerator.Fill(nonce);

            // Derive message keys using HKDF
            var messageKeys = GetMessageKeys(conversationKey, nonce);
            
            // Pad plaintext to hide length
            var padded = Pad(plaintextBytes);
            
            // Encrypt with ChaCha20
            var ciphertext = ChaCha20Encrypt(padded, messageKeys.ChaChaKey, messageKeys.ChaChaNonce);
            
            // Calculate MAC for authentication
            var mac = ComputeHmac(messageKeys.HmacKey, nonce, ciphertext);

            // Build result: version (1) + nonce (32) + ciphertext (variable) + mac (32)
            var result = new byte[1 + 32 + ciphertext.Length + 32];
            result[0] = 2; // version
            Buffer.BlockCopy(nonce, 0, result, 1, 32);
            Buffer.BlockCopy(ciphertext, 0, result, 33, ciphertext.Length);
            Buffer.BlockCopy(mac, 0, result, 33 + ciphertext.Length, 32);

            return Convert.ToBase64String(result);
        }

        private static string DecryptV2(byte[] data, byte[] conversationKey)
        {
            // Minimum: version (1) + nonce (32) + min_padded_plaintext (32) + mac (32) = 97 bytes
            if (data.Length < 99)
                throw new ArgumentException("Invalid payload length for NIP-44 v2", nameof(data));

            // Extract components
            var nonce = data.AsSpan(1, 32).ToArray();
            var ciphertextLength = data.Length - 65; // total - (version + nonce + mac)
            var ciphertext = data.AsSpan(33, ciphertextLength).ToArray();
            var expectedMac = data.AsSpan(33 + ciphertextLength, 32).ToArray();

            // Derive message keys
            var messageKeys = GetMessageKeys(conversationKey, nonce);
            
            // Verify MAC
            var calculatedMac = ComputeHmac(messageKeys.HmacKey, nonce, ciphertext);
            if (!CryptographicOperations.FixedTimeEquals(expectedMac, calculatedMac))
                throw new CryptographicException("MAC verification failed");

            // Decrypt and unpad
            var padded = ChaCha20Decrypt(ciphertext, messageKeys.ChaChaKey, messageKeys.ChaChaNonce);
            var plaintext = Unpad(padded);

            return Encoding.UTF8.GetString(plaintext);
        }

        private static (byte[] ChaChaKey, byte[] ChaChaNonce, byte[] HmacKey) GetMessageKeys(byte[] conversationKey, byte[] nonce)
        {
            // conversation_key is already the output of HKDF-Extract
            // Now we just need to use HKDF-Expand with it as the PRK
            // get_message_keys(conversation_key, nonce) -> HKDF-Expand(PRK=conversation_key, info=nonce, L=76)
            
            if (conversationKey.Length != 32)
                throw new ArgumentException("Conversation key must be 32 bytes", nameof(conversationKey));
            if (nonce.Length != 32)
                throw new ArgumentException("Nonce must be 32 bytes", nameof(nonce));
            
            var okm = new byte[76]; // 32 (ChaCha key) + 12 (nonce) + 32 (HMAC key)
            
            // Use HKDF.Expand since conversationKey is already a PRK from HKDF.Extract
            HKDF.Expand(HashAlgorithmName.SHA256, conversationKey, okm, nonce);

            var chaChaKey = okm.AsSpan(0, 32).ToArray();
            var chaChaNonce = okm.AsSpan(32, 12).ToArray();
            var hmacKey = okm.AsSpan(44, 32).ToArray();

            return (chaChaKey, chaChaNonce, hmacKey);
        }

        private static byte[] Pad(byte[] plaintext)
        {
            var unpaddedLen = plaintext.Length;
            
            // NIP-44 padding algorithm based on official specification
            // See: https://github.com/nostr-protocol/nips/blob/master/44.md
            int paddedPlaintextLen = CalcPaddedLen(unpaddedLen);

            // Result: 2-byte prefix + paddedPlaintextLen bytes
            var result = new byte[2 + paddedPlaintextLen];
            
            // Write length prefix in first 2 bytes
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(0, 2), (ushort)unpaddedLen);
            
            // Copy plaintext starting at byte 2
            Buffer.BlockCopy(plaintext, 0, result, 2, unpaddedLen);
            // Remaining bytes are already zero (padding)

            return result;
        }

        private static int CalcPaddedLen(int unpaddedLen)
        {
            // Implementation of calc_padded_len from NIP-44 specification
            // https://github.com/nostr-protocol/nips/blob/master/44.md
            
            if (unpaddedLen <= 32)
                return 32;

            // Calculate next power of 2: next_power = 1 << (floor(log2(unpadded_len - 1)) + 1)
            // This is equivalent to finding the smallest power of 2 that is >= unpaddedLen
            int nextPower = 1;
            int logValue = 0;
            int temp = unpaddedLen - 1;
            
            // Calculate floor(log2(unpadded_len - 1))
            while (temp > 0)
            {
                logValue++;
                temp >>= 1;
            }
            
            // nextPower = 1 << (logValue + 1) but logValue is off by 1, so just use logValue
            nextPower = 1 << logValue;

            // Determine chunk size
            int chunk;
            if (nextPower <= 256)
            {
                chunk = 32;
            }
            else
            {
                chunk = nextPower / 8;
            }

            // Round up to nearest chunk multiple
            return chunk * ((unpaddedLen - 1) / chunk + 1);
        }

        private static byte[] Unpad(byte[] padded)
        {
            if (padded.Length < 2)
                throw new ArgumentException("Invalid padded data", nameof(padded));

            var unpaddedLen = BinaryPrimitives.ReadUInt16BigEndian(padded.AsSpan(0, 2));
            
            if (unpaddedLen == 0 || unpaddedLen > MaxPlaintextSize)
                throw new ArgumentException("Invalid padding: unpadded length out of range");

            var unpadded = padded.AsSpan(2, unpaddedLen);
            
            // Validate that the padded length matches the expected padding calculation
            var expectedPaddedLen = 2 + CalcPaddedLen(unpaddedLen);
            if (padded.Length != expectedPaddedLen)
                throw new ArgumentException($"Invalid padding: expected {expectedPaddedLen} bytes, got {padded.Length} bytes");

            return unpadded.ToArray();
        }

        #endregion

        #region Version 1 (Legacy)

        private static string EncryptV1(string plaintext, byte[] conversationKey)
        {
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            
            // Generate random nonce
            var nonce = new byte[32];
            RandomNumberGenerator.Fill(nonce);

            // Derive message keys (simpler than v2)
            var messageKeys = GetMessageKeysV1(conversationKey, nonce);
            
            // Encrypt with ChaCha20 (no padding in v1)
            var ciphertext = ChaCha20Encrypt(plaintextBytes, messageKeys.ChaChaKey, messageKeys.ChaChaNonce);
            
            // Calculate MAC
            var mac = ComputeHmac(messageKeys.HmacKey, ciphertext);

            // Build result: version (1) + nonce (32) + ciphertext (variable) + mac (32)
            var result = new byte[1 + 32 + ciphertext.Length + 32];
            result[0] = 1; // version
            Buffer.BlockCopy(nonce, 0, result, 1, 32);
            Buffer.BlockCopy(ciphertext, 0, result, 33, ciphertext.Length);
            Buffer.BlockCopy(mac, 0, result, 33 + ciphertext.Length, 32);

            return Convert.ToBase64String(result);
        }

        private static string DecryptV1(byte[] data, byte[] conversationKey)
        {
            if (data.Length < 66) // version (1) + nonce (32) + min_ciphertext (1) + mac (32)
                throw new ArgumentException("Invalid payload length for NIP-44 v1", nameof(data));

            // Extract components
            var nonce = data.AsSpan(1, 32).ToArray();
            var ciphertextLength = data.Length - 65;
            var ciphertext = data.AsSpan(33, ciphertextLength).ToArray();
            var expectedMac = data.AsSpan(33 + ciphertextLength, 32).ToArray();

            // Derive message keys
            var messageKeys = GetMessageKeysV1(conversationKey, nonce);
            
            // Verify MAC
            var calculatedMac = ComputeHmac(messageKeys.HmacKey, ciphertext);
            if (!CryptographicOperations.FixedTimeEquals(expectedMac, calculatedMac))
                throw new CryptographicException("MAC verification failed");

            // Decrypt
            var plaintext = ChaCha20Decrypt(ciphertext, messageKeys.ChaChaKey, messageKeys.ChaChaNonce);
            return Encoding.UTF8.GetString(plaintext);
        }

        private static (byte[] ChaChaKey, byte[] ChaChaNonce, byte[] HmacKey) GetMessageKeysV1(byte[] conversationKey, byte[] nonce)
        {
            // Simple key derivation for v1
            var combined = new byte[conversationKey.Length + nonce.Length];
            Buffer.BlockCopy(conversationKey, 0, combined, 0, conversationKey.Length);
            Buffer.BlockCopy(nonce, 0, combined, conversationKey.Length, nonce.Length);

            var hash = SHA256.HashData(combined);
            var chaChaKey = hash;
            var chaChaNonce = nonce.AsSpan(0, 12).ToArray();
            var hmacKey = conversationKey;

            return (chaChaKey, chaChaNonce, hmacKey);
        }

        #endregion

        #region Cryptographic Primitives

        private static byte[] ChaCha20Encrypt(byte[] plaintext, byte[] key, byte[] nonce)
        {
            // ChaCha20 stream cipher implementation
            // Since .NET doesn't have standalone ChaCha20, we use ChaCha20Poly1305
            // but only use the encryption part (not the authentication tag)
            var ciphertext = new byte[plaintext.Length];
            ChaCha20Transform(plaintext, ciphertext, key, nonce, 0);
            return ciphertext;
        }

        private static byte[] ChaCha20Decrypt(byte[] ciphertext, byte[] key, byte[] nonce)
        {
            // ChaCha20 decryption is the same as encryption (XOR stream cipher)
            var plaintext = new byte[ciphertext.Length];
            ChaCha20Transform(ciphertext, plaintext, key, nonce, 0);
            return plaintext;
        }

        private static void ChaCha20Transform(byte[] input, byte[] output, byte[] key, byte[] nonce, uint counter)
        {
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes", nameof(key));
            if (nonce.Length != 12)
                throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));
            if (input.Length != output.Length)
                throw new ArgumentException("Input and output must be same length");

            var state = new uint[16];
            
            // Initialize state
            // "expand 32-byte k"
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;
            
            // Key
            for (int i = 0; i < 8; i++)
                state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4, 4));
            
            // Counter
            state[12] = counter;
            
            // Nonce
            for (int i = 0; i < 3; i++)
                state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(i * 4, 4));

            var keystream = new byte[64];
            int inputOffset = 0;
            int outputOffset = 0;
            int remaining = input.Length;

            while (remaining > 0)
            {
                // Generate keystream block
                ChaCha20Block(state, keystream);
                state[12]++; // Increment counter

                int blockSize = Math.Min(remaining, 64);
                
                // XOR input with keystream
                for (int i = 0; i < blockSize; i++)
                    output[outputOffset + i] = (byte)(input[inputOffset + i] ^ keystream[i]);

                inputOffset += blockSize;
                outputOffset += blockSize;
                remaining -= blockSize;
            }
        }

        private static void ChaCha20Block(uint[] state, byte[] output)
        {
            var working = new uint[16];
            Array.Copy(state, working, 16);

            // 20 rounds (10 double rounds)
            for (int i = 0; i < 10; i++)
            {
                // Column rounds
                QuarterRound(working, 0, 4, 8, 12);
                QuarterRound(working, 1, 5, 9, 13);
                QuarterRound(working, 2, 6, 10, 14);
                QuarterRound(working, 3, 7, 11, 15);
                
                // Diagonal rounds
                QuarterRound(working, 0, 5, 10, 15);
                QuarterRound(working, 1, 6, 11, 12);
                QuarterRound(working, 2, 7, 8, 13);
                QuarterRound(working, 3, 4, 9, 14);
            }

            // Add original state
            for (int i = 0; i < 16; i++)
                working[i] += state[i];

            // Serialize to bytes (little-endian)
            for (int i = 0; i < 16; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4, 4), working[i]);
        }

        private static void QuarterRound(uint[] state, int a, int b, int c, int d)
        {
            state[a] += state[b]; state[d] ^= state[a]; state[d] = RotateLeft(state[d], 16);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = RotateLeft(state[b], 12);
            state[a] += state[b]; state[d] ^= state[a]; state[d] = RotateLeft(state[d], 8);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = RotateLeft(state[b], 7);
        }

        private static uint RotateLeft(uint value, int bits)
        {
            return (value << bits) | (value >> (32 - bits));
        }

        private static byte[] ComputeHmac(byte[] key, params byte[][] data)
        {
            using var hmac = new HMACSHA256(key);
            using var stream = new System.IO.MemoryStream();
            foreach (var item in data)
                stream.Write(item);
            stream.Position = 0;
            return hmac.ComputeHash(stream);
        }

        #endregion
    }
}

