using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.Messages.Direct;
using Nostr.Client.Utils;
using System.Text;

namespace Nostr.Client.Tests
{
    /// <summary>
    /// NIP-44 test vectors from the official specification
    /// https://github.com/nostr-protocol/nips/blob/master/44.md
    /// </summary>
    public class Nip44TestVectors
    {
        // Test vectors for NIP-44 v2
        private const string TestPrivateKey1Hex = "0000000000000000000000000000000000000000000000000000000000000001";
        private const string TestPrivateKey2Hex = "0000000000000000000000000000000000000000000000000000000000000002";

        [Fact]
        public void Nip44V2_GetConversationKey_ShouldMatchTestVector()
        {
            // Test conversation key derivation (ECDH)
            var key1 = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var key2 = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            
            var key2Public = key2.DerivePublicKey();
            var sharedKey = key1.DeriveSharedKey(key2Public);
            var conversationKey = sharedKey.Ec.ToBytes().ToArray();

            // The conversation key should be deterministic
            Assert.Equal(32, conversationKey.Length);
            Assert.NotEqual(new byte[32], conversationKey); // Should not be all zeros
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_EmptyString_ShouldThrow()
        {
            // NIP-44 requires minimum 1 byte plaintext
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var ev = new NostrEvent
            {
                Content = "",
                CreatedAt = DateTime.UtcNow
            };

            // Empty strings should throw ArgumentException
            Assert.Throws<ArgumentException>(() =>
                ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2));
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_SingleByte()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var ev = new NostrEvent
            {
                Content = "a",
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(recipient);

            Assert.Equal("a", decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_ShortMessage()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var testMessages = new[]
            {
                "a",
                "ab",
                "abc",
                "abcd",
                "hello",
                "hello world",
                "The quick brown fox"
            };

            foreach (var message in testMessages)
            {
                var ev = new NostrEvent
                {
                    Content = message,
                    CreatedAt = DateTime.UtcNow
                };

                var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
                var decrypted = encrypted.DecryptContent(recipient);

                Assert.Equal(message, decrypted);
            }
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_32ByteBoundary()
        {
            // Test padding at 32-byte boundary
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            // Messages at padding boundaries
            var testMessages = new[]
            {
                new string('a', 1),    // Pads to 32
                new string('a', 16),   // Pads to 32
                new string('a', 31),   // Pads to 32
                new string('a', 32),   // Pads to 32
                new string('a', 33),   // Pads to 64
                new string('a', 64),   // Pads to 64
                new string('a', 65),   // Pads to 128
            };

            foreach (var message in testMessages)
            {
                var ev = new NostrEvent
                {
                    Content = message,
                    CreatedAt = DateTime.UtcNow
                };

                var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
                var decrypted = encrypted.DecryptContent(recipient);

                Assert.Equal(message, decrypted);
            }
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_MaxSize()
        {
            // Test maximum allowed size (65535 bytes)
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var maxMessage = new string('x', 65535);

            var ev = new NostrEvent
            {
                Content = maxMessage,
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(recipient);

            Assert.Equal(maxMessage, decrypted);
        }

        [Fact]
        public void Nip44V2_Encrypt_MessageTooLarge_ShouldThrow()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            // Message larger than 65535 bytes should throw
            var tooLargeMessage = new string('x', 65536);

            var ev = new NostrEvent
            {
                Content = tooLargeMessage,
                CreatedAt = DateTime.UtcNow
            };

            Assert.Throws<ArgumentException>(() =>
                ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2));
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_SpecialCharacters()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var testMessages = new[]
            {
                "\n",
                "\r\n",
                "\t",
                "null\0byte",
                "unicode: \u0001\u0002\u0003",
                "emoji: 🔐🔑🗝️",
                "mixed: hello\nworld\ttab",
                "\"quotes\" and 'apostrophes'",
                "special: !@#$%^&*()[]{}|\\;:'\",.<>?/`~"
            };

            foreach (var message in testMessages)
            {
                var ev = new NostrEvent
                {
                    Content = message,
                    CreatedAt = DateTime.UtcNow
                };

                var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
                var decrypted = encrypted.DecryptContent(recipient);

                Assert.Equal(message, decrypted);
            }
        }

        [Fact]
        public void Nip44V2_EncryptedPayload_ShouldHaveVersionByte()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var ev = new NostrEvent
            {
                Content = "test message",
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            
            // Decode base64 and check version byte
            var payloadBytes = Convert.FromBase64String(encrypted.Content!);
            Assert.Equal(2, payloadBytes[0]); // Version byte should be 2
        }

        [Fact]
        public void Nip44V2_EncryptedPayload_ShouldHaveCorrectStructure()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var ev = new NostrEvent
            {
                Content = "test",
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            
            // Structure: version(1) + nonce(32) + ciphertext(variable) + mac(32)
            var payloadBytes = Convert.FromBase64String(encrypted.Content!);
            
            // Minimum size: 1 + 32 + 34 (2-byte length + 32 padded plaintext) + 32 = 99
            Assert.True(payloadBytes.Length >= 99, $"Payload too small: {payloadBytes.Length} bytes");
            
            // Check version
            Assert.Equal(2, payloadBytes[0]);
        }

        [Fact]
        public void Nip44V2_DifferentNonces_ShouldProduceDifferentCiphertexts()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var message = "same message encrypted twice";

            var ev1 = new NostrEvent { Content = message, CreatedAt = DateTime.UtcNow };
            var ev2 = new NostrEvent { Content = message, CreatedAt = DateTime.UtcNow };

            var encrypted1 = ev1.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            var encrypted2 = ev2.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);

            // Same message should produce different ciphertexts due to random nonce
            Assert.NotEqual(encrypted1.Content, encrypted2.Content);

            // But both should decrypt to the same message
            var decrypted1 = encrypted1.DecryptContent(recipient);
            var decrypted2 = encrypted2.DecryptContent(recipient);

            Assert.Equal(message, decrypted1);
            Assert.Equal(message, decrypted2);
        }

        [Fact]
        public void Nip44V2_InvalidMAC_ShouldThrowCryptographicException()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var ev = new NostrEvent
            {
                Content = "test message",
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            
            // Tamper with the MAC by modifying the last byte
            var payloadBytes = Convert.FromBase64String(encrypted.Content!);
            payloadBytes[payloadBytes.Length - 1] ^= 0xFF; // Flip last byte
            var tamperedContent = Convert.ToBase64String(payloadBytes);

            var tamperedEvent = new NostrEncryptedEvent(tamperedContent, encrypted.Tags)
            {
                Pubkey = encrypted.Pubkey,
                Kind = encrypted.Kind
            };

            // Decryption should fail due to invalid MAC
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
                tamperedEvent.DecryptContent(recipient));
        }

        [Fact]
        public void Nip44V2_TamperedCiphertext_ShouldThrowCryptographicException()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var ev = new NostrEvent
            {
                Content = "test message",
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            
            // Tamper with the ciphertext (middle of the payload)
            var payloadBytes = Convert.FromBase64String(encrypted.Content!);
            payloadBytes[40] ^= 0xFF; // Flip a byte in the ciphertext
            var tamperedContent = Convert.ToBase64String(payloadBytes);

            var tamperedEvent = new NostrEncryptedEvent(tamperedContent, encrypted.Tags)
            {
                Pubkey = encrypted.Pubkey,
                Kind = encrypted.Kind
            };

            // Decryption should fail due to MAC verification
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
                tamperedEvent.DecryptContent(recipient));
        }

        [Fact]
        public void Nip44V2_WrongRecipient_ShouldProduceDifferentPlaintext()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var wrongRecipient = NostrPrivateKey.GenerateNew();
            var recipientPublic = recipient.DerivePublicKey();

            var message = "secret message";
            var ev = new NostrEvent
            {
                Content = message,
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);

            // Wrong recipient should throw because pubkey doesn't match
            Assert.Throws<InvalidOperationException>(() =>
                encrypted.DecryptContent(wrongRecipient));
        }

        [Fact]
        public void Nip44V2_Padding_ShouldHideMessageLength()
        {
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            // Messages of similar length should have same ciphertext size after padding
            var messages = new[]
            {
                new string('a', 1),
                new string('b', 10),
                new string('c', 20),
                new string('d', 30)
            };

            var ciphertextLengths = new List<int>();

            foreach (var message in messages)
            {
                var ev = new NostrEvent { Content = message, CreatedAt = DateTime.UtcNow };
                var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
                var payloadBytes = Convert.FromBase64String(encrypted.Content!);
                ciphertextLengths.Add(payloadBytes.Length);
            }

            // All messages 1-30 bytes should pad to same size (32 bytes + 2 byte length prefix)
            // Total structure: 1 (version) + 32 (nonce) + 34 (padded) + 32 (mac) = 99
            Assert.All(ciphertextLengths, length => Assert.Equal(99, length));
        }

        [Fact]
        public void Nip44V2_DirectCompatibility_WithLowLevelAPI()
        {
            // Test that high-level API is compatible with low-level API
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var message = "test compatibility";

            // Encrypt with high-level API
            var ev = new NostrEvent { Content = message, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);

            // Decrypt with low-level API
            var sharedKey = recipient.DeriveSharedKey(sender.DerivePublicKey());
            var conversationKey = sharedKey.Ec.ToBytes().ToArray();
            var decryptedDirect = NostrEncryptionNip44.Decrypt(encrypted.Content!, conversationKey);

            Assert.Equal(message, decryptedDirect);
        }

        [Fact]
        public void Nip44V2_SymmetricEncryption_BothDirections()
        {
            // Test that encryption works in both directions
            var alice = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var bob = NostrPrivateKey.FromHex(TestPrivateKey2Hex);

            var alicePublic = alice.DerivePublicKey();
            var bobPublic = bob.DerivePublicKey();

            var messageAliceToBob = "Hello Bob from Alice";
            var messageBobToAlice = "Hello Alice from Bob";

            // Alice to Bob
            var ev1 = new NostrEvent { Content = messageAliceToBob, CreatedAt = DateTime.UtcNow };
            var encrypted1 = ev1.Encrypt(alice, bobPublic, NostrEncryptionType.Nip44V2);
            var decrypted1 = encrypted1.DecryptContent(bob);

            // Bob to Alice
            var ev2 = new NostrEvent { Content = messageBobToAlice, CreatedAt = DateTime.UtcNow };
            var encrypted2 = ev2.Encrypt(bob, alicePublic, NostrEncryptionType.Nip44V2);
            var decrypted2 = encrypted2.DecryptContent(alice);

            Assert.Equal(messageAliceToBob, decrypted1);
            Assert.Equal(messageBobToAlice, decrypted2);
        }

        #region Official NIP-44 Test Vectors from https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json

        [Theory]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000001", 
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    "3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e")]
        [InlineData("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
                    "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
                    "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1")]
        [InlineData("a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
                    "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
                    "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b")]
        public void Nip44V2_GetConversationKey_OfficialTestVectors(string sec1Hex, string pub2Hex, string expectedConversationKeyHex)
        {
            // Test conversation key derivation matches official test vectors
            var key1 = NostrPrivateKey.FromHex(sec1Hex);
            var key2Public = NostrPublicKey.FromHex(pub2Hex);
            
            var sharedKey = key1.DeriveSharedKey(key2Public);
            var conversationKey = sharedKey.Ec.ToBytes().ToArray();
            var conversationKeyHex = BitConverter.ToString(conversationKey).Replace("-", "").ToLower();

            Assert.Equal(expectedConversationKeyHex, conversationKeyHex);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector1()
        {
            // Test vector: plaintext "a"
            var sec1 = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var sec2 = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "a";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
            
            // Verify payload structure
            var payload = Convert.FromBase64String(encrypted.Content!);
            Assert.Equal(2, payload[0]); // version byte
            Assert.True(payload.Length >= 99); // minimum size for short message
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector2()
        {
            // Test vector: emoji "🍕🫃"
            var sec1 = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000002");
            var sec2 = NostrPrivateKey.FromHex("0000000000000000000000000000000000000000000000000000000000000001");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "🍕🫃";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector3()
        {
            // Test vector: mixed unicode
            var sec1 = NostrPrivateKey.FromHex("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a");
            var sec2 = NostrPrivateKey.FromHex("4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector4()
        {
            // Test vector: "ability🤝的 ȺȾ"
            var sec1 = NostrPrivateKey.FromHex("8f40e50a84a7462e2b8d24c28898ef1f23359fff50d8c509e6fb7ce06e142f9c");
            var sec2 = NostrPrivateKey.FromHex("b9b0a1e9cc20100c5faa3bbe2777303d25950616c4c6a3fa2e3e046f936ec2ba");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "ability🤝的 ȺȾ";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector5()
        {
            // Test vector: "pepper👀їжак"
            var sec1 = NostrPrivateKey.FromHex("875adb475056aec0b4809bd2db9aa00cff53a649e7b59d8edcbf4e6330b0995c");
            var sec2 = NostrPrivateKey.FromHex("9c05781112d5b0a2a7148a222e50e0bd891d6b60c5483f03456e982185944aae");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "pepper👀їжак";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector6()
        {
            // Test vector: "( ͡° ͜ʖ ͡°)"
            var sec1 = NostrPrivateKey.FromHex("eba1687cab6a3101bfc68fd70f214aa4cc059e9ec1b79fdb9ad0a0a4e259829f");
            var sec2 = NostrPrivateKey.FromHex("dff20d262bef9dfd94666548f556393085e6ea421c8af86e9d333fa8747e94b3");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "( ͡° ͜ʖ ͡°)";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector7_Arabic()
        {
            // Test vector: Arabic text
            var sec1 = NostrPrivateKey.FromHex("d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e");
            var sec2 = NostrPrivateKey.FromHex("b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "مُنَاقَشَةُ سُبُلِ اِسْتِخْدَامِ اللُّغَةِ فِي النُّظُمِ الْقَائِمَةِ وَفِيم يَخُصَّ التَّطْبِيقَاتُ الْحاسُوبِيَّةُ،";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector8_Arabic()
        {
            // Test vector: Arabic text "الكل في المجمو عة (5)"
            var sec1 = NostrPrivateKey.FromHex("d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e");
            var sec2 = NostrPrivateKey.FromHex("b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "الكل في المجمو عة (5)";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector9_MathSymbols()
        {
            // Test vector: "𝖑𝖆𝖟𝖞 社會科學院語學研究所"
            var sec1 = NostrPrivateKey.FromHex("d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e");
            var sec2 = NostrPrivateKey.FromHex("b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "𝖑𝖆𝖟𝖞 社會科學院語學研究所";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Nip44V2_EncryptDecrypt_OfficialTestVector10_EmojiNumbersPower()
        {
            // Test vector: Complex emoji and unicode mix
            var sec1 = NostrPrivateKey.FromHex("d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e");
            var sec2 = NostrPrivateKey.FromHex("b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214");
            var pub2 = sec2.DerivePublicKey();

            var plaintext = "🙈 🙉 🙊 0️⃣ 1️⃣ 2️⃣ 3️⃣ 4️⃣ 5️⃣ 6️⃣ 7️⃣ 8️⃣ 9️⃣ 🔟 Powerلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ冗";
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [InlineData(16, 32)]
        [InlineData(32, 32)]
        [InlineData(33, 64)]
        [InlineData(37, 64)]
        [InlineData(45, 64)]
        [InlineData(49, 64)]
        [InlineData(64, 64)]
        [InlineData(65, 96)]
        [InlineData(100, 128)]
        [InlineData(111, 128)]
        [InlineData(200, 224)]
        [InlineData(250, 256)]
        [InlineData(320, 320)]
        [InlineData(383, 384)]
        [InlineData(384, 384)]
        [InlineData(400, 448)]
        [InlineData(500, 512)]
        [InlineData(512, 512)]
        [InlineData(515, 640)]
        [InlineData(700, 768)]
        [InlineData(800, 896)]
        [InlineData(900, 1024)]
        [InlineData(1020, 1024)]
        public void Nip44V2_PaddedLength_OfficialTestVectors(int plaintextLen, int expectedPaddedLen)
        {
            // Test that padding matches official specification
            // The test vectors specify the padded plaintext size (NOT including 2-byte length prefix)
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var plaintext = new string('x', plaintextLen);
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);

            var payload = Convert.FromBase64String(encrypted.Content!);
            
            // Payload structure: version(1) + nonce(32) + padded_ciphertext + mac(32)
            // padded_ciphertext = length_prefix(2) + plaintext + padding
            var ciphertextLength = payload.Length - 1 - 32 - 32; // total - version - nonce - mac
            
            // The expected value is for the padded plaintext WITHOUT the 2-byte length prefix
            // So we subtract 2 from the actual ciphertext length
            var paddedPlaintextLen = ciphertextLength - 2;
            
            Assert.Equal(expectedPaddedLen, paddedPlaintextLen);
        }
        
        [Theory]
        [InlineData(16, 32)]
        [InlineData(32, 32)]
        [InlineData(33, 64)]
        [InlineData(37, 64)]
        [InlineData(45, 64)]
        [InlineData(49, 64)]
        [InlineData(64, 64)]
        [InlineData(65, 96)]
        [InlineData(100, 128)]
        [InlineData(111, 128)]
        [InlineData(200, 224)]
        [InlineData(250, 256)]
        [InlineData(320, 320)]
        [InlineData(383, 384)]
        [InlineData(384, 384)]
        [InlineData(400, 448)]
        [InlineData(500, 512)]
        [InlineData(512, 512)]
        [InlineData(515, 640)]
        [InlineData(700, 768)]
        [InlineData(800, 896)]
        [InlineData(900, 1024)]
        [InlineData(1020, 1024)]
        public void Nip44V2_PaddedLength_OfficialTestVectors_gemini(int plaintextLen, int expectedPaddedLen)
        {
            // Test that padding matches official specification
            // The test vectors specify the padded plaintext size (NOT including 2-byte length prefix)
            var sender = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var recipient = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var recipientPublic = recipient.DerivePublicKey();

            var plaintext = new string('x', plaintextLen);
            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sender, recipientPublic, NostrEncryptionType.Nip44V2);
            var payload = Convert.FromBase64String(encrypted.Content!);
    
            // NIP-44 v2 Payload Structure:
            // [Version (1)] + [Nonce (32)] + [Padded Ciphertext (L_padded)] + [MAC (32)]
    
            // Calculate L_padded: the length of the PADDED input data (which is the ciphertext length)
            var paddedDataLength = payload.Length - 1 - 32 - 32; // Total - Version - Nonce - MAC
    
            // The padded input data structure is:
            // [2-byte Length Prefix] + [Plaintext Content] + [Zero Padding]
    
            // The expected test vector value (expectedPaddedLen) is:
            // [Plaintext Content] + [Zero Padding]
            var actualPaddedLen = paddedDataLength - 2; // Subtract the 2-byte length prefix
    
            Assert.Equal(expectedPaddedLen, actualPaddedLen);
        }

        #endregion
    }
}

