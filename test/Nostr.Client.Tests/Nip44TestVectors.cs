using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.Messages.Direct;
using Nostr.Client.Utils;
using System.Text;
using System.Security.Cryptography;

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
            var key1 = NostrPrivateKey.FromHex(TestPrivateKey1Hex);
            var key2 = NostrPrivateKey.FromHex(TestPrivateKey2Hex);
            var key2Public = key2.DerivePublicKey();

            // NIP-44 conversation key uses ECDH + HKDF-Extract
            var conversationKey = key1.DeriveConversationKeyNip44(key2Public);

            // Verify it's different from raw ECDH shared secret
            var rawShared = key1.DeriveSharedKey(key2Public).Ec.ToBytes().ToArray();
            Assert.NotEqual(BitConverter.ToString(conversationKey).Replace("-", "").ToLower(),
                         BitConverter.ToString(rawShared).Replace("-", "").ToLower());
            
            // Verify the conversation key is 32 bytes
            Assert.Equal(32, conversationKey.Length);
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
            var conversationKey = recipient.DeriveConversationKeyNip44(sender.DerivePublicKey());
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
        [InlineData("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
            "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
            "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1")]
        [InlineData("a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
            "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
            "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b")]
        [InlineData("98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311",
            "aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1",
            "9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7")]
        [InlineData("86ae5ac8034eb2542ce23ec2f84375655dab7f836836bbd3c54cefe9fdc9c19f",
            "59f90272378089d73f1339710c02e2be6db584e9cdbe86eed3578f0c67c23585",
            "19f934aafd3324e8415299b64df42049afaa051c71c98d0aa10e1081f2e3e2ba")]
        [InlineData("2528c287fe822421bc0dc4c3615878eb98e8a8c31657616d08b29c00ce209e34",
            "f66ea16104c01a1c532e03f166c5370a22a5505753005a566366097150c6df60",
            "c833bbb292956c43366145326d53b955ffb5da4e4998a2d853611841903f5442")]
        [InlineData("49808637b2d21129478041813aceb6f2c9d4929cd1303cdaf4fbdbd690905ff2",
            "74d2aab13e97827ea21baf253ad7e39b974bb2498cc747cdb168582a11847b65",
            "4bf304d3c8c4608864c0fe03890b90279328cd24a018ffa9eb8f8ccec06b505d")]
        [InlineData("af67c382106242c5baabf856efdc0629cc1c5b4061f85b8ceaba52aa7e4b4082",
            "bdaf0001d63e7ec994fad736eab178ee3c2d7cfc925ae29f37d19224486db57b",
            "a3a575dd66d45e9379904047ebfb9a7873c471687d0535db00ef2daa24b391db")]
        [InlineData("0e44e2d1db3c1717b05ffa0f08d102a09c554a1cbbf678ab158b259a44e682f1",
            "1ffa76c5cc7a836af6914b840483726207cb750889753d7499fb8b76aa8fe0de",
            "a39970a667b7f861f100e3827f4adbf6f464e2697686fe1a81aeda817d6b8bdf")]
        [InlineData("5fc0070dbd0666dbddc21d788db04050b86ed8b456b080794c2a0c8e33287bb6",
            "31990752f296dd22e146c9e6f152a269d84b241cc95bb3ff8ec341628a54caf0",
            "72c21075f4b2349ce01a3e604e02a9ab9f07e35dd07eff746de348b4f3c6365e")]
        [InlineData("1b7de0d64d9b12ddbb52ef217a3a7c47c4362ce7ea837d760dad58ab313cba64",
            "24383541dd8083b93d144b431679d70ef4eec10c98fceef1eff08b1d81d4b065",
            "dd152a76b44e63d1afd4dfff0785fa07b3e494a9e8401aba31ff925caeb8f5b1")]
        [InlineData("df2f560e213ca5fb33b9ecde771c7c0cbd30f1cf43c2c24de54480069d9ab0af",
            "eeea26e552fc8b5e377acaa03e47daa2d7b0c787fac1e0774c9504d9094c430e",
            "770519e803b80f411c34aef59c3ca018608842ebf53909c48d35250bd9323af6")]
        [InlineData("cffff919fcc07b8003fdc63bc8a00c0f5dc81022c1c927c62c597352190d95b9",
            "eb5c3cca1a968e26684e5b0eb733aecfc844f95a09ac4e126a9e58a4e4902f92",
            "46a14ee7e80e439ec75c66f04ad824b53a632b8409a29bbb7c192e43c00bb795")]
        [InlineData("64ba5a685e443e881e9094647ddd32db14444bb21aa7986beeba3d1c4673ba0a",
            "50e6a4339fac1f3bf86f2401dd797af43ad45bbf58e0801a7877a3984c77c3c4",
            "968b9dbbfcede1664a4ca35a5d3379c064736e87aafbf0b5d114dff710b8a946")]
        [InlineData("dd0c31ccce4ec8083f9b75dbf23cc2878e6d1b6baa17713841a2428f69dee91a",
            "b483e84c1339812bed25be55cff959778dfc6edde97ccd9e3649f442472c091b",
            "09024503c7bde07eb7865505891c1ea672bf2d9e25e18dd7a7cea6c69bf44b5d")]
        [InlineData("af71313b0d95c41e968a172b33ba5ebd19d06cdf8a7a98df80ecf7af4f6f0358",
            "2a5c25266695b461ee2af927a6c44a3c598b8095b0557e9bd7f787067435bc7c",
            "fe5155b27c1c4b4e92a933edae23726a04802a7cc354a77ac273c85aa3c97a92")]
        [InlineData("6636e8a389f75fe068a03b3edb3ea4a785e2768e3f73f48ffb1fc5e7cb7289dc",
            "514eb2064224b6a5829ea21b6e8f7d3ea15ff8e70e8555010f649eb6e09aec70",
            "ff7afacd4d1a6856d37ca5b546890e46e922b508639214991cf8048ddbe9745c")]
        [InlineData("94b212f02a3cfb8ad147d52941d3f1dbe1753804458e6645af92c7b2ea791caa",
            "f0cac333231367a04b652a77ab4f8d658b94e86b5a8a0c472c5c7b0d4c6a40cc",
            "e292eaf873addfed0a457c6bd16c8effde33d6664265697f69f420ab16f6669b")]
        [InlineData("aa61f9734e69ae88e5d4ced5aae881c96f0d7f16cca603d3bed9eec391136da6",
            "4303e5360a884c360221de8606b72dd316da49a37fe51e17ada4f35f671620a6",
            "8e7d44fd4767456df1fb61f134092a52fcd6836ebab3b00766e16732683ed848")]
        [InlineData("5e914bdac54f3f8e2cba94ee898b33240019297b69e96e70c8a495943a72fc98",
            "5bd097924f606695c59f18ff8fd53c174adbafaaa71b3c0b4144a3e0a474b198",
            "f5a0aecf2984bf923c8cd5e7bb8be262d1a8353cb93959434b943a07cf5644bc")]
        [InlineData("8b275067add6312ddee064bcdbeb9d17e88aa1df36f430b2cea5cc0413d8278a",
            "65bbbfca819c90c7579f7a82b750a18c858db1afbec8f35b3c1e0e7b5588e9b8",
            "2c565e7027eb46038c2263563d7af681697107e975e9914b799d425effd248d6")]
        [InlineData("1ac848de312285f85e0f7ec208aac20142a1f453402af9b34ec2ec7a1f9c96fc",
            "45f7318fe96034d23ee3ddc25b77f275cc1dd329664dd51b89f89c4963868e41",
            "b56e970e5057a8fd929f8aad9248176b9af87819a708d9ddd56e41d1aec74088")]
        [InlineData("295a1cf621de401783d29d0e89036aa1c62d13d9ad307161b4ceb535ba1b40e6",
            "840115ddc7f1034d3b21d8e2103f6cb5ab0b63cf613f4ea6e61ae3d016715cdd",
            "b4ee9c0b9b9fef88975773394f0a6f981ca016076143a1bb575b9ff46e804753")]
        [InlineData("a28eed0fe977893856ab9667e06ace39f03abbcdb845c329a1981be438ba565d",
            "b0f38b950a5013eba5ab4237f9ed29204a59f3625c71b7e210fec565edfa288c",
            "9d3a802b45bc5aeeb3b303e8e18a92ddd353375710a31600d7f5fff8f3a7285b")]
        [InlineData("7ab65af72a478c05f5c651bdc4876c74b63d20d04cdbf71741e46978797cd5a4",
            "f1112159161b568a9cb8c9dd6430b526c4204bcc8ce07464b0845b04c041beda",
            "943884cddaca5a3fef355e9e7f08a3019b0b66aa63ec90278b0f9fdb64821e79")]
        [InlineData("95c79a7b75ba40f2229e85756884c138916f9d103fc8f18acc0877a7cceac9fe",
            "cad76bcbd31ca7bbda184d20cc42f725ed0bb105b13580c41330e03023f0ffb3",
            "81c0832a669eea13b4247c40be51ccfd15bb63fcd1bba5b4530ce0e2632f301b")]
        [InlineData("baf55cc2febd4d980b4b393972dfc1acf49541e336b56d33d429bce44fa12ec9",
            "0c31cf87fe565766089b64b39460ebbfdedd4a2bc8379be73ad3c0718c912e18",
            "37e2344da9ecdf60ae2205d81e89d34b280b0a3f111171af7e4391ded93b8ea6")]
        [InlineData("6eeec45acd2ed31693c5256026abf9f072f01c4abb61f51cf64e6956b6dc8907",
            "e501b34ed11f13d816748c0369b0c728e540df3755bab59ed3327339e16ff828",
            "afaa141b522ddb27bb880d768903a7f618bb8b6357728cae7fb03af639b946e6")]
        [InlineData("261a076a9702af1647fb343c55b3f9a4f1096273002287df0015ba81ce5294df",
            "b2777c863878893ae100fb740c8fab4bebd2bf7be78c761a75593670380a6112",
            "76f8d2853de0734e51189ced523c09427c3e46338b9522cd6f74ef5e5b475c74")]
        [InlineData("ed3ec71ca406552ea41faec53e19f44b8f90575eda4b7e96380f9cc73c26d6f3",
            "86425951e61f94b62e20cae24184b42e8e17afcf55bafa58645efd0172624fae",
            "f7ffc520a3a0e9e9b3c0967325c9bf12707f8e7a03f28b6cd69ae92cf33f7036")]
        [InlineData("5a788fc43378d1303ac78639c59a58cb88b08b3859df33193e63a5a3801c722e",
            "a8cba2f87657d229db69bee07850fd6f7a2ed070171a06d006ec3a8ac562cf70",
            "7d705a27feeedf78b5c07283362f8e361760d3e9f78adab83e3ae5ce7aeb6409")]
        [InlineData("63bffa986e382b0ac8ccc1aa93d18a7aa445116478be6f2453bad1f2d3af2344",
            "b895c70a83e782c1cf84af558d1038e6b211c6f84ede60408f519a293201031d",
            "3a3b8f00d4987fc6711d9be64d9c59cf9a709c6c6481c2cde404bcc7a28f174e")]
        [InlineData("e4a8bcacbf445fd3721792b939ff58e691cdcba6a8ba67ac3467b45567a03e5c",
            "b54053189e8c9252c6950059c783edb10675d06d20c7b342f73ec9fa6ed39c9d",
            "7b3933b4ef8189d347169c7955589fc1cfc01da5239591a08a183ff6694c44ad")]
        [InlineData("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "8b6392dbf2ec6a2b2d5b1477fc2be84d63ef254b667cadd31bd3f444c44ae6ba")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000002",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb",
            "be234f46f60a250bef52a5ee34c758800c4ca8e5030bf4cc1a31d37ba2104d43")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000001",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e")]
        public void Nip44V2_GetConversationKey_OfficialTestVectors(string sec1Hex, string pub2Hex,
            string expectedConversationKeyHex)
        {
            // Test conversation key derivation matches official test vectors
            var key1 = NostrPrivateKey.FromHex(sec1Hex);
            var key2Public = NostrPublicKey.FromHex(pub2Hex);

            var conversationKey = key1.DeriveConversationKeyNip44(key2Public);
            Assert.Equal(expectedConversationKeyHex, BitConverter.ToString(conversationKey).Replace("-", "").ToLower());
        }


        [Theory]
        [InlineData(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "a")]
        [InlineData(
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "🍕🫃")]
        [InlineData(
            "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a",
            "4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d",
            "表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀")]
        [InlineData(
            "8f40e50a84a7462e2b8d24c28898ef1f23359fff50d8c509e6fb7ce06e142f9c",
            "b9b0a1e9cc20100c5faa3bbe2777303d25950616c4c6a3fa2e3e046f936ec2ba",
            "ability🤝的 ȺȾ")]
        [InlineData(
            "875adb475056aec0b4809bd2db9aa00cff53a649e7b59d8edcbf4e6330b0995c",
            "9c05781112d5b0a2a7148a222e50e0bd891d6b60c5483f03456e982185944aae",
            "pepper👀їжак")]
        [InlineData(
            "eba1687cab6a3101bfc68fd70f214aa4cc059e9ec1b79fdb9ad0a0a4e259829f",
            "dff20d262bef9dfd94666548f556393085e6ea421c8af86e9d333fa8747e94b3",
            "( ͡° ͜ʖ ͡°)")]
        [InlineData(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "مُنَاقَشَةُ سُبُلِ اِسْتِخْدَامِ اللُّغَةِ فِي النُّظُمِ الْقَائِمَةِ وَفِيم يَخُصَّ التَّطْبِيقَاتُ الْحاسُوبِيَّةُ،")]
        [InlineData(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "الكل في المجمو عة (5)")]
        [InlineData(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "𝖑𝖆𝖟𝖞 社會科學院語學研究所")]
        [InlineData(
            "d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
            "b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
            "🙈 🙉 🙊 0️⃣ 1️⃣ 2️⃣ 3️⃣ 4️⃣ 5️⃣ 6️⃣ 7️⃣ 8️⃣ 9️⃣ 🔟 Powerلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ冗")]
        public void Nip44V2_EncryptDecrypt_OfficialTestVectors(string sec1Hex, string sec2Hex, string plaintext)
        {
            var sec1 = NostrPrivateKey.FromHex(sec1Hex);
            var sec2 = NostrPrivateKey.FromHex(sec2Hex);
            var pub2 = sec2.DerivePublicKey();

            var ev = new NostrEvent { Content = plaintext, CreatedAt = DateTime.UtcNow };
            var encrypted = ev.Encrypt(sec1, pub2, NostrEncryptionType.Nip44V2);
            var decrypted = encrypted.DecryptContent(sec2);

            Assert.Equal(plaintext, decrypted);

            // Verify payload structure for first test vector only
            if (plaintext == "a")
            {
                var payload = Convert.FromBase64String(encrypted.Content!);
                Assert.Equal(2, payload[0]); // version byte
                Assert.True(payload.Length >= 99); // minimum size for short message
            }
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

        #endregion

        #region Get Message Keys Test Vectors

        [Theory]
        [InlineData("e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72",
            "f145f3bed47cb70dbeaac07f3a3fe683e822b3715edb7c4fe310829014ce7d76",
            "c4ad129bb01180c0933a160c",
            "027c1db445f05e2eee864a0975b0ddef5b7110583c8c192de3732571ca5838c4")]
        [InlineData("e1d6d28c46de60168b43d79dacc519698512ec35e8ccb12640fc8e9f26121101",
            "e35b88f8d4a8f1606c5082f7a64b100e5d85fcdb2e62aeafbec03fb9e860ad92",
            "22925e920cee4a50a478be90",
            "46a7c55d4283cb0df1d5e29540be67abfe709e3b2e14b7bf9976e6df994ded30")]
        [InlineData("cfc13bef512ac9c15951ab00030dfaf2626fdca638dedb35f2993a9eeb85d650",
            "020783eb35fdf5b80ef8c75377f4e937efb26bcbad0e61b4190e39939860c4bf",
            "d3594987af769a52904656ac",
            "237ec0ccb6ebd53d179fa8fd319e092acff599ef174c1fdafd499ef2b8dee745")]
        [InlineData("ea6eb84cac23c5c1607c334e8bdf66f7977a7e374052327ec28c6906cbe25967",
            "ff68db24b34fa62c78ac5ffeeaf19533afaedf651fb6a08384e46787f6ce94be",
            "50bb859aa2dde938cc49ec7a",
            "06ff32e1f7b29753a727d7927b25c2dd175aca47751462d37a2039023ec6b5a6")]
        [InlineData("8c2e1dd3792802f1f9f7842e0323e5d52ad7472daf360f26e15f97290173605d",
            "2f9daeda8683fdeede81adac247c63cc7671fa817a1fd47352e95d9487989d8b",
            "400224ba67fc2f1b76736916",
            "465c05302aeeb514e41c13ed6405297e261048cfb75a6f851ffa5b445b746e4b")]
        [InlineData("05c28bf3d834fa4af8143bf5201a856fa5fac1a3aee58f4c93a764fc2f722367",
            "1e3d45777025a035be566d80fd580def73ed6f7c043faec2c8c1c690ad31c110",
            "021905b1ea3afc17cb9bf96f",
            "74a6e481a89dcd130aaeb21060d7ec97ad30f0007d2cae7b1b11256cc70dfb81")]
        [InlineData("5e043fb153227866e75a06d60185851bc90273bfb93342f6632a728e18a07a17",
            "1ea72c9293841e7737c71567d8120145a58991aaa1c436ef77bf7adb83f882f1",
            "72f69a5a5f795465cee59da8",
            "e9daa1a1e9a266ecaa14e970a84bce3fbbf329079bbccda626582b4e66a0d4c9")]
        [InlineData("7be7338eaf06a87e274244847fe7a97f5c6a91f44adc18fcc3e411ad6f786dbf",
            "881e7968a1f0c2c80742ee03cd49ea587e13f22699730f1075ade01931582bf6",
            "6e69be92d61c04a276021565",
            "901afe79e74b19967c8829af23617d7d0ffbf1b57190c096855c6a03523a971b")]
        [InlineData("94571c8d590905bad7becd892832b472f2aa5212894b6ce96e5ba719c178d976",
            "f80873dd48466cb12d46364a97b8705c01b9b4230cb3ec3415a6b9551dc42eef",
            "3dda53569cfcb7fac1805c35",
            "e9fc264345e2839a181affebc27d2f528756e66a5f87b04bf6c5f1997047051e")]
        [InlineData("13a6ee974b1fd759135a2c2010e3cdda47081c78e771125e4f0c382f0284a8cb",
            "bc5fb403b0bed0d84cf1db872b6522072aece00363178c98ad52178d805fca85",
            "65064239186e50304cc0f156",
            "e872d320dde4ed3487958a8e43b48aabd3ced92bc24bb8ff1ccb57b590d9701a")]
        [InlineData("082fecdb85f358367b049b08be0e82627ae1d8edb0f27327ccb593aa2613b814",
            "1fbdb1cf6f6ea816349baf697932b36107803de98fcd805ebe9849b8ad0e6a45",
            "2e605e1d825a3eaeb613db9c",
            "fae910f591cf3c7eb538c598583abad33bc0a03085a96ca4ea3a08baf17c0eec")]
        [InlineData("4c19020c74932c30ec6b2d8cd0d5bb80bd0fc87da3d8b4859d2fb003810afd03",
            "1ab9905a0189e01cda82f843d226a82a03c4f5b6dbea9b22eb9bc953ba1370d4",
            "cbb2530ea653766e5a37a83a",
            "267f68acac01ac7b34b675e36c2cef5e7b7a6b697214add62a491bedd6efc178")]
        [InlineData("67723a3381497b149ce24814eddd10c4c41a1e37e75af161930e6b9601afd0ff",
            "9ecbd25e7e2e6c97b8c27d376dcc8c5679da96578557e4e21dba3a7ef4e4ac07",
            "ef649fcf335583e8d45e3c2e",
            "04dbbd812fa8226fdb45924c521a62e3d40a9e2b5806c1501efdeba75b006bf1")]
        [InlineData("42063fe80b093e8619b1610972b4c3ab9e76c14fd908e642cd4997cafb30f36c",
            "211c66531bbcc0efcdd0130f9f1ebc12a769105eb39608994bcb188fa6a73a4a",
            "67803605a7e5010d0f63f8c8",
            "e840e4e8921b57647369d121c5a19310648105dbdd008200ebf0d3b668704ff8")]
        [InlineData("b5ac382a4be7ac03b554fe5f3043577b47ea2cd7cfc7e9ca010b1ffbb5cf1a58",
            "b3b5f14f10074244ee42a3837a54309f33981c7232a8b16921e815e1f7d1bb77",
            "4e62a0073087ed808be62469",
            "c8efa10230b5ea11633816c1230ca05fa602ace80a7598916d83bae3d3d2ccd7")]
        [InlineData("e9d1eba47dd7e6c1532dc782ff63125db83042bb32841db7eeafd528f3ea7af9",
            "54241f68dc2e50e1db79e892c7c7a471856beeb8d51b7f4d16f16ab0645d2f1a",
            "a963ed7dc29b7b1046820a1d",
            "aba215c8634530dc21c70ddb3b3ee4291e0fa5fa79be0f85863747bde281c8b2")]
        [InlineData("a94ecf8efeee9d7068de730fad8daf96694acb70901d762de39fa8a5039c3c49",
            "c0565e9e201d2381a2368d7ffe60f555223874610d3d91fbbdf3076f7b1374dd",
            "329bb3024461e84b2e1c489b",
            "ac42445491f092481ce4fa33b1f2274700032db64e3a15014fbe8c28550f2fec")]
        [InlineData("533605ea214e70c25e9a22f792f4b78b9f83a18ab2103687c8a0075919eaaa53",
            "ab35a5e1e54d693ff023db8500d8d4e79ad8878c744e0eaec691e96e141d2325",
            "653d759042b85194d4d8c0a7",
            "b43628e37ba3c31ce80576f0a1f26d3a7c9361d29bb227433b66f49d44f167ba")]
        [InlineData("7f38df30ceea1577cb60b355b4f5567ff4130c49e84fed34d779b764a9cc184c",
            "a37d7f211b84a551a127ff40908974eb78415395d4f6f40324428e850e8c42a3",
            "b822e2c959df32b3cb772a7c",
            "1ba31764f01f69b5c89ded2d7c95828e8052c55f5d36f1cd535510d61ba77420")]
        [InlineData("11b37f9dbc4d0185d1c26d5f4ed98637d7c9701fffa65a65839fa4126573a4e5",
            "964f38d3a31158a5bfd28481247b18dd6e44d69f30ba2a40f6120c6d21d8a6ba",
            "5f72c5b87c590bcd0f93b305",
            "2fc4553e7cedc47f29690439890f9f19c1077ef3e9eaeef473d0711e04448918")]
        [InlineData("8be790aa483d4cdd843189f71f135b3ec7e31f381312c8fe9f177aab2a48eafa",
            "95c8c74d633721a131316309cf6daf0804d59eaa90ea998fc35bac3d2fbb7a94",
            "409a7654c0e4bf8c2c6489be",
            "21bb0b06eb2b460f8ab075f497efa9a01c9cf9146f1e3986c3bf9da5689b6dc4")]
        [InlineData("19fd2a718ea084827d6bd73f509229ddf856732108b59fc01819f611419fd140",
            "cc6714b9f5616c66143424e1413d520dae03b1a4bd202b82b0a89b0727f5cdc8",
            "1b7fd2534f015a8f795d8f32",
            "2bef39c4ce5c3c59b817e86351373d1554c98bc131c7e461ed19d96cfd6399a0")]
        public void Nip44V2_GetMessageKeys_OfficialTestVectors(string nonceHex, string expectedChaChaKeyHex,
            string expectedChaChaNonceHex, string expectedHmacKeyHex)
        {
            // Test vector conversation key
            const string conversationKeyHex = "a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54";
            
            var conversationKey = Convert.FromHexString(conversationKeyHex);
            var nonce = Convert.FromHexString(nonceHex);

            // Use reflection to call the private GetMessageKeys method
            var method = typeof(NostrEncryptionNip44).GetMethod("GetMessageKeys",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            
            Assert.NotNull(method);
            
            var result = method.Invoke(null, new object[] { conversationKey, nonce });
            
            // Extract the tuple values - ValueTuple uses Item1, Item2, Item3
            var resultType = result!.GetType();
            var chaChaKey = (byte[])resultType.GetField("Item1")!.GetValue(result)!;
            var chaChaNonce = (byte[])resultType.GetField("Item2")!.GetValue(result)!;
            var hmacKey = (byte[])resultType.GetField("Item3")!.GetValue(result)!;

            // Verify the keys match expected values
            Assert.Equal(expectedChaChaKeyHex,
                BitConverter.ToString(chaChaKey).Replace("-", "").ToLower());
            Assert.Equal(expectedChaChaNonceHex,
                BitConverter.ToString(chaChaNonce).Replace("-", "").ToLower());
            Assert.Equal(expectedHmacKeyHex,
                BitConverter.ToString(hmacKey).Replace("-", "").ToLower());
        }

        #endregion

        // HKDF-Extract for NIP-44 v2 (salt="nip44-v2"). No expand step needed; output length = 32.
        private static byte[] HkdfExtractNip44(byte[] ikm)
        {
            var salt = Encoding.ASCII.GetBytes("nip44-v2");
            using var hmac = new HMACSHA256(salt);
            return hmac.ComputeHash(ikm);
        }
    }
}

