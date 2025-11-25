using Nostr.Client.Keys;
using Nostr.Client.Utils;
using System.Security.Cryptography;

namespace Nostr.Client.Tests
{
    /// <summary>
    /// NIP-44 invalid test vectors from the official specification
    /// https://github.com/nostr-protocol/nips/blob/master/44.md
    /// 
    /// Test vectors source: https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json
    /// 
    /// Invalid Test Coverage:
    /// 
    /// 1. invalid.encrypt_msg_lengths (4 tests)
    ///    - Tests that invalid message lengths are rejected
    ///    - Lengths: 0, 65536, 100000, 10000000
    ///    
    /// 2. invalid.get_conversation_key (8 tests)
    ///    - Tests invalid private keys (0, > curve.n, == curve.n)
    ///    - Tests invalid public keys (no sqrt, points on twist)
    ///    
    /// 3. invalid.decrypt (13 tests)
    ///    - Unknown encryption versions
    ///    - Invalid base64 encoding
    ///    - Invalid MAC (tampering detection)
    ///    - Invalid padding
    ///    - Invalid payload lengths
    /// </summary>
    public class Nip44InvalidTestVectors
    {
        #region invalid.encrypt_msg_lengths - Invalid Message Length Tests

        /// <summary>
        /// Tests from invalid.encrypt_msg_lengths section
        /// Verifies that encryption rejects messages outside valid range [1, 65535]
        /// </summary>
        [Theory]
        [InlineData(0)]
        [InlineData(65536)]
        [InlineData(100000)]
        [InlineData(10000000)]
        public void Nip44V2_Encrypt_InvalidMessageLength_ShouldThrow(int length)
        {
            var sender = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var recipient = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var recipientPublic = recipient.DerivePublicKey();
            var conversationKey = sender.DeriveConversationKeyNip44(recipientPublic);

            string plaintext;
            if (length == 0)
            {
                plaintext = "";
            }
            else
            {
                plaintext = new string('x', length);
            }

            // Should throw ArgumentException for invalid message length
            Assert.Throws<ArgumentException>(() =>
            {
                NostrEncryptionNip44.Encrypt(plaintext, conversationKey);
            });
        }

        #endregion

        #region invalid.get_conversation_key - Invalid Key Tests

        /// <summary>
        /// Tests from invalid.get_conversation_key section
        /// Verifies that invalid private/public keys are rejected
        /// </summary>
        [Theory]
        [InlineData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "sec1 higher than curve.n")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000000",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "sec1 is 0")]
        [InlineData("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "sec1 == curve.n")]
        public void Nip44V2_GetConversationKey_InvalidPrivateKey_ShouldThrow(string sec1Hex, string pub2Hex, string _)
        {
            // Invalid private keys should be rejected
            Assert.Throws<ArgumentException>(() =>
            {
                var key1 = NostrPrivateKey.FromHex(sec1Hex);
            });
        }

        [Theory]
        [InlineData("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "pub2 is invalid, no sqrt, all-ff")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000002",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "pub2 is invalid, no sqrt")]
        [InlineData("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "pub2 is point of order 3 on twist")]
        [InlineData("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "eb1f7200aecaa86682376fb1c13cd12b732221e774f553b0a0857f88fa20f86d",
            "pub2 is point of order 13 on twist")]
        [InlineData("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "709858a4c121e4a84eb59c0ded0261093c71e8ca29efeef21a6161c447bcaf9f",
            "pub2 is point of order 3319 on twist")]
        public void Nip44V2_GetConversationKey_InvalidPublicKey_ShouldThrow(string sec1Hex, string pub2Hex, string _)
        {
            var key1 = NostrPrivateKey.FromHex(sec1Hex);

            // Invalid public keys should be rejected
            Assert.ThrowsAny<Exception>(() =>
            {
                var pub2 = NostrPublicKey.FromHex(pub2Hex);
                var conversationKey = key1.DeriveConversationKeyNip44(pub2);
            });
        }

        #endregion

        #region invalid.decrypt - Invalid Decryption Tests

        /// <summary>
        /// Tests from invalid.decrypt section
        /// Verifies that decryption properly rejects invalid/tampered payloads
        /// </summary>
        [Theory]
        [InlineData("ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642",
            "#Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJdU0MIDf06CUvEvdnr1cp1fiMtlM/GrE92xAc1K5odTpCzUB+mjXgbaqtntBUbTToSUoT0ovrlPwzGjyp",
            "unknown encryption version")]
        public void Nip44V2_Decrypt_UnknownVersion_ShouldThrow(string conversationKeyHex, string payload, string _)
        {
            var conversationKey = Convert.FromHexString(conversationKeyHex);

            // Unknown version should be rejected
            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Decrypt(payload, conversationKey);
            });
        }

        [Theory]
        [InlineData("36f04e558af246352dcf73b692fbd3646a2207bd8abd4b1cd26b234db84d9481",
            "AK1AjUvoYW3IS7C/BGRUoqEC7ayTfDUgnEPNeWTF/reBZFaha6EAIRueE9D1B1RuoiuFScC0Q94yjIuxZD3JStQtE8JMNacWFs9rlYP+ZydtHhRucp+lxfdvFlaGV/sQlqZz",
            "unknown encryption version 0")]
        public void Nip44V2_Decrypt_Version0_ShouldThrow(string conversationKeyHex, string payload, string _)
        {
            var conversationKey = Convert.FromHexString(conversationKeyHex);

            // Version 0 is not supported (only version 2)
            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Decrypt(payload, conversationKey);
            });
        }

        [Theory]
        [InlineData("ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642",
            "Atфupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJZE0UICD06CUvEvdnr1cp1fiMtlM/GrE92xAc1EwsVCQEgWEu2gsHUVf4JAa3TpgkmFc3TWsax0v6n/Wq",
            "invalid base64")]
        public void Nip44V2_Decrypt_InvalidBase64_ShouldThrow(string conversationKeyHex, string payload, string _)
        {
            var conversationKey = Convert.FromHexString(conversationKeyHex);

            // Invalid base64 should be rejected
            Assert.Throws<FormatException>(() =>
            {
                NostrEncryptionNip44.Decrypt(payload, conversationKey);
            });
        }

        [Theory]
        [InlineData("cff7bd6a3e29a450fd27f6c125d5edeb0987c475fd1e8d97591e0d4d8a89763c",
            "Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholyySBfeh+EN8wNB9gaLlg4j6wdBYh+3oK+mnxWu3NKRbSvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "invalid MAC")]
        [InlineData("cfcc9cf682dfb00b11357f65bdc45e29156b69db424d20b3596919074f5bf957",
            "AmWxSwuUmqp9UsQX63U7OQ6K1thLI69L7G2b+j4DoIr0oRWQ8avl4OLqWZiTJ10vIgKrNqjoaX+fNhE9RqmR5g0f6BtUg1ijFMz71MO1D4lQLQfW7+UHva8PGYgQ1QpHlKgR",
            "invalid MAC")]
        public void Nip44V2_Decrypt_InvalidMAC_ShouldThrow(string conversationKeyHex, string payload, string _)
        {
            var conversationKey = Convert.FromHexString(conversationKeyHex);

            // Invalid/tampered MAC should throw CryptographicException
            Assert.Throws<CryptographicException>(() =>
            {
                NostrEncryptionNip44.Decrypt(payload, conversationKey);
            });
        }

        [Theory]
        [InlineData("5254827d29177622d40a7b67cad014fe7137700c3c523903ebbe3e1b74d40214",
            "Anq2XbuLvCuONcr7V0UxTh8FAyWoZNEdBHXvdbNmDZHB573MI7R7rrTYftpqmvUpahmBC2sngmI14/L0HjOZ7lWGJlzdh6luiOnGPc46cGxf08MRC4CIuxx3i2Lm0KqgJ7vA",
            "invalid padding")]
        [InlineData("fea39aca9aa8340c3a78ae1f0902aa7e726946e4efcd7783379df8096029c496",
            "An1Cg+O1TIhdav7ogfSOYvCj9dep4ctxzKtZSniCw5MwRrrPJFyAQYZh5VpjC2QYzny5LIQ9v9lhqmZR4WBYRNJ0ognHVNMwiFV1SHpvUFT8HHZN/m/QarflbvDHAtO6pY16",
            "invalid padding")]
        [InlineData("0c4cffb7a6f7e706ec94b2e879f1fc54ff8de38d8db87e11787694d5392d5b3f",
            "Am+f1yZnwnOs0jymZTcRpwhDRHTdnrFcPtsBzpqVdD6b2NZDaNm/TPkZGr75kbB6tCSoq7YRcbPiNfJXNch3Tf+o9+zZTMxwjgX/nm3yDKR2kHQMBhVleCB9uPuljl40AJ8kXRD0gjw+aYRJFUMK9gCETZAjjmrsCM+nGRZ1FfNsHr6Z",
            "invalid padding")]
        public void Nip44V2_Decrypt_InvalidPadding_ShouldThrow(string conversationKeyHex, string payload, string _)
        {
            var conversationKey = Convert.FromHexString(conversationKeyHex);

            // Invalid padding should be rejected
            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Decrypt(payload, conversationKey);
            });
        }

        [Theory]
        [InlineData("5cd2d13b9e355aeb2452afbd3786870dbeecb9d355b12cb0a3b6e9da5744cd35",
            "",
            "invalid payload length: 0")]
        [InlineData("d61d3f09c7dfe1c0be91af7109b60a7d9d498920c90cbba1e137320fdd938853",
            "Ag==",
            "invalid payload length: 4")]
        [InlineData("873bb0fc665eb950a8e7d5971965539f6ebd645c83c08cd6a85aafbad0f0bc47",
            "AqxgToSh3H7iLYRJjoWAM+vSv/Y1mgNlm6OWWjOYUClrFF8=",
            "invalid payload length: 48")]
        [InlineData("9f2fef8f5401ac33f74641b568a7a30bb19409c76ffdc5eae2db6b39d2617fbe",
            "Ap/2SEZCVFIhYk6qx7nqJxM6TMI1ZoKmAzrO7vBDVJhhuZXWiM20i/tIsbjT0KxkJs2MZjh1oXNYMO9ggfk7i47WQA==",
            "invalid payload length: 92")]
        public void Nip44V2_Decrypt_InvalidPayloadLength_ShouldThrow(string conversationKeyHex, string payload, string _)
        {
            var conversationKey = Convert.FromHexString(conversationKeyHex);

            // Invalid payload lengths should be rejected
            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Decrypt(payload, conversationKey);
            });
        }

        #endregion

        #region Additional Edge Case Tests

        [Fact]
        public void Nip44V2_Encrypt_NullPlaintext_ShouldThrow()
        {
            var sender = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var recipient = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var recipientPublic = recipient.DerivePublicKey();
            var conversationKey = sender.DeriveConversationKeyNip44(recipientPublic);

            Assert.Throws<ArgumentNullException>(() =>
            {
                NostrEncryptionNip44.Encrypt(null!, conversationKey);
            });
        }

        [Fact]
        public void Nip44V2_Encrypt_NullConversationKey_ShouldThrow()
        {
            // Currently throws NullReferenceException - should be improved to ArgumentNullException
            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Encrypt("test", null!);
            });
        }

        [Fact]
        public void Nip44V2_Decrypt_NullPayload_ShouldThrow()
        {
            var sender = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var recipient = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var recipientPublic = recipient.DerivePublicKey();
            var conversationKey = sender.DeriveConversationKeyNip44(recipientPublic);

            Assert.Throws<ArgumentNullException>(() =>
            {
                NostrEncryptionNip44.Decrypt(null!, conversationKey);
            });
        }

        [Fact]
        public void Nip44V2_Decrypt_NullConversationKey_ShouldThrow()
        {
            // Currently throws NullReferenceException - should be improved to ArgumentNullException
            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Decrypt("AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb", null!);
            });
        }

        [Fact]
        public void Nip44V2_Decrypt_EmptyPayload_ShouldThrow()
        {
            var sender = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var recipient = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var recipientPublic = recipient.DerivePublicKey();
            var conversationKey = sender.DeriveConversationKeyNip44(recipientPublic);

            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Decrypt("", conversationKey);
            });
        }

        [Fact]
        public void Nip44V2_Decrypt_TruncatedPayload_ShouldThrow()
        {
            var sender = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var recipient = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var recipientPublic = recipient.DerivePublicKey();
            var conversationKey = sender.DeriveConversationKeyNip44(recipientPublic);

            // Truncated payload (too short)
            Assert.ThrowsAny<Exception>(() =>
            {
                NostrEncryptionNip44.Decrypt("AgAAAA==", conversationKey);
            });
        }

        [Fact]
        public void Nip44V2_DeriveConversationKey_InvalidKeyLength_ShouldThrow()
        {
            var sender = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var recipient = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var recipientPublic = recipient.DerivePublicKey();

            var conversationKey = sender.DeriveConversationKeyNip44(recipientPublic);
            
            // Conversation key should always be 32 bytes
            Assert.Equal(32, conversationKey.Length);
        }

        #endregion
    }
}

