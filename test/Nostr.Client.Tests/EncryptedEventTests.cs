using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.Messages.Direct;

namespace Nostr.Client.Tests
{
    public class EncryptedEventTests
    {

        [Fact]
        public void ReceivedEvent_ShouldBeDecryptedBySenderAndReceiver()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var userRandom = NostrPrivateKey.FromBech32("nsec10jj7d532su7gunn6rnpezgwyr0nvd55r4whppj4t64xux03sxvwsd4n5my");

            var eventFromUser1 = new NostrEncryptedEvent(
                "RzHxmB2DffNSIvLliVkzkA==?iv=zKlGqw6+aBBpjaFS0p1Haw==",
                new(
                    new NostrEventTag("p", "d27790fcb3f9afa0d709b2e9c5995151bc5ad008079bd0a474aa101d80e0eed3")
                ))
            {
                Id = "d7c4ecbf0ea0539125444127a44b060270918867a73ce2c0bac7127066cb71bc",
                Kind = NostrKind.EncryptedDm,
                CreatedAt = new DateTime(2023, 3, 10, 10, 58, 4, DateTimeKind.Utc),
                Pubkey = "7e8575871843980ffee6f8bcd37cc381589b5653bb8a1b3e585bf5e2a5c15f78",
                Sig =
                    "7a6cffef01dafcf5a2ab096df4cc1dd411461604675df014311ad85ccbb616f82ae85ccba81a72b00f62b21e648d4160b8b54e324e85319ca4617575167c4c65"
            };

            Assert.Equal("RzHxmB2DffNSIvLliVkzkA==", eventFromUser1.EncryptedContent);
            Assert.Equal("zKlGqw6+aBBpjaFS0p1Haw==", eventFromUser1.InitializationVector);

            var decryptedByUser1 = eventFromUser1.DecryptContent(user1);
            var decryptedByUser2 = eventFromUser1.DecryptContent(user2);

            Assert.Throws<InvalidOperationException>(() => eventFromUser1.DecryptContent(userRandom));
            Assert.Equal("Hey from user 1", decryptedByUser1);
            Assert.Equal("Hey from user 1", decryptedByUser2);
        }

        [Fact]
        public void SendEvent_ShouldBeEncryptedToDirectMessageCorrectly()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var user2Public = user2.DerivePublicKey();
            var now = new DateTime(2023, 3, 10, 10, 58, 4, DateTimeKind.Utc);

            var ev = new NostrEvent()
            {
                Kind = NostrKind.ShortTextNote,
                Content = "Hey from user 1",
                CreatedAt = now
            };

            var encrypted = ev.EncryptDirect(user1, user2Public);

            Assert.Equal(now, encrypted.CreatedAt);
            Assert.Equal(NostrKind.EncryptedDm, encrypted.Kind);
            Assert.Equal(user2Public.Hex, encrypted.RecipientPubkey);
            Assert.Equal(user2Public.Hex, encrypted.Tags?.FindFirstTagValue(NostrEventTag.ProfileIdentifier));
            Assert.Null(encrypted.Id);
            Assert.Null(encrypted.Sig);

            var decryptedByUser1 = encrypted.DecryptContent(user1);
            var decryptedByUser2 = encrypted.DecryptContent(user2);

            Assert.Equal("Hey from user 1", decryptedByUser1);
            Assert.Equal("Hey from user 1", decryptedByUser2);
        }

        [Fact]
        public void SendEvent_ShouldBeEncryptedCorrectly()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var user2Public = user2.DerivePublicKey();
            var now = new DateTime(2023, 3, 10, 10, 58, 4, DateTimeKind.Utc);

            var ev = new NostrEvent()
            {
                Kind = NostrKind.BadgeAward,
                Content = "Hey from user 1",
                CreatedAt = now
            };

            var encrypted = ev.Encrypt(user1, user2Public);

            Assert.Equal(now, encrypted.CreatedAt);
            Assert.Equal(NostrKind.BadgeAward, encrypted.Kind);
            Assert.Equal(user2Public.Hex, encrypted.RecipientPubkey);
            Assert.Equal(user2Public.Hex, encrypted.Tags?.FindFirstTagValue(NostrEventTag.ProfileIdentifier));
            Assert.Null(encrypted.Id);
            Assert.Null(encrypted.Sig);

            var decryptedByUser1 = encrypted.DecryptContent(user1);
            var decryptedByUser2 = encrypted.DecryptContent(user2);

            Assert.Equal("Hey from user 1", decryptedByUser1);
            Assert.Equal("Hey from user 1", decryptedByUser2);
        }

        [Fact]
        public void SendEvent_WithNip44V2_ShouldEncryptAndDecryptCorrectly()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var user2Public = user2.DerivePublicKey();
            var now = new DateTime(2023, 3, 10, 10, 58, 4, DateTimeKind.Utc);

            var ev = new NostrEvent()
            {
                Kind = NostrKind.ShortTextNote,
                Content = "Hello NIP-44 v2!",
                CreatedAt = now
            };

            var encrypted = ev.Encrypt(user1, user2Public, NostrEncryptionType.Nip44V2);

            Assert.Equal(now, encrypted.CreatedAt);
            Assert.Equal(NostrKind.ShortTextNote, encrypted.Kind);
            Assert.Equal(user2Public.Hex, encrypted.RecipientPubkey);
            Assert.NotNull(encrypted.Content);
            Assert.Null(encrypted.InitializationVector); // NIP-44 doesn't use IV separator
            Assert.NotNull(encrypted.EncryptedContent);

            var decryptedByUser1 = encrypted.DecryptContent(user1);
            var decryptedByUser2 = encrypted.DecryptContent(user2);

            Assert.Equal("Hello NIP-44 v2!", decryptedByUser1);
            Assert.Equal("Hello NIP-44 v2!", decryptedByUser2);
        }

        [Fact]
        public void SendEvent_WithNip44V1_ShouldEncryptAndDecryptCorrectly()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var user2Public = user2.DerivePublicKey();
            var now = new DateTime(2023, 3, 10, 10, 58, 4, DateTimeKind.Utc);

            var ev = new NostrEvent()
            {
                Kind = NostrKind.ShortTextNote,
                Content = "Hello NIP-44 v1!",
                CreatedAt = now
            };

            var encrypted = ev.Encrypt(user1, user2Public, NostrEncryptionType.Nip44V1);

            Assert.Equal(now, encrypted.CreatedAt);
            Assert.Equal(NostrKind.ShortTextNote, encrypted.Kind);
            Assert.Equal(user2Public.Hex, encrypted.RecipientPubkey);
            Assert.NotNull(encrypted.Content);
            Assert.Null(encrypted.InitializationVector); // NIP-44 doesn't use IV separator

            var decryptedByUser1 = encrypted.DecryptContent(user1);
            var decryptedByUser2 = encrypted.DecryptContent(user2);

            Assert.Equal("Hello NIP-44 v1!", decryptedByUser1);
            Assert.Equal("Hello NIP-44 v1!", decryptedByUser2);
        }

        [Fact]
        public void SendDirectMessage_WithNip44V2_ShouldEncryptAndDecryptCorrectly()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var user2Public = user2.DerivePublicKey();
            var now = new DateTime(2023, 3, 10, 10, 58, 4, DateTimeKind.Utc);

            var ev = new NostrEvent()
            {
                Kind = NostrKind.ShortTextNote,
                Content = "Secret DM with NIP-44 v2",
                CreatedAt = now
            };

            var encrypted = ev.EncryptDirect(user1, user2Public, NostrEncryptionType.Nip44V2);

            Assert.Equal(now, encrypted.CreatedAt);
            Assert.Equal(NostrKind.EncryptedDm, encrypted.Kind);
            Assert.Equal(user2Public.Hex, encrypted.RecipientPubkey);

            var decryptedByUser1 = encrypted.DecryptContent(user1);
            var decryptedByUser2 = encrypted.DecryptContent(user2);

            Assert.Equal("Secret DM with NIP-44 v2", decryptedByUser1);
            Assert.Equal("Secret DM with NIP-44 v2", decryptedByUser2);
        }

        [Fact]
        public void Nip44V2_WithLongMessage_ShouldEncryptAndDecryptCorrectly()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var user2Public = user2.DerivePublicKey();

            // Create a long message
            var longMessage = string.Join(" ", Enumerable.Repeat("This is a test message.", 100));

            var ev = new NostrEvent()
            {
                Kind = NostrKind.ShortTextNote,
                Content = longMessage,
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(user1, user2Public, NostrEncryptionType.Nip44V2);

            var decryptedByUser1 = encrypted.DecryptContent(user1);
            var decryptedByUser2 = encrypted.DecryptContent(user2);

            Assert.Equal(longMessage, decryptedByUser1);
            Assert.Equal(longMessage, decryptedByUser2);
        }

        [Fact]
        public void Nip44V2_WithUnicodeMessage_ShouldEncryptAndDecryptCorrectly()
        {
            var user1 = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
            var user2 = NostrPrivateKey.FromBech32("nsec1phvgvjs596qq0tq2h98xyunqg8r38yvwfg7pxt8mucfvr0jtlvks9k7uzu");
            var user2Public = user2.DerivePublicKey();

            var unicodeMessage = "Hello 👋 World 🌍 こんにちは 你好 🚀";

            var ev = new NostrEvent()
            {
                Kind = NostrKind.ShortTextNote,
                Content = unicodeMessage,
                CreatedAt = DateTime.UtcNow
            };

            var encrypted = ev.Encrypt(user1, user2Public, NostrEncryptionType.Nip44V2);

            var decryptedByUser1 = encrypted.DecryptContent(user1);
            var decryptedByUser2 = encrypted.DecryptContent(user2);

            Assert.Equal(unicodeMessage, decryptedByUser1);
            Assert.Equal(unicodeMessage, decryptedByUser2);
        }
    }
}
