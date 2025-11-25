﻿using Newtonsoft.Json;
using Nostr.Client.Keys;
using Nostr.Client.Utils;

namespace Nostr.Client.Messages.Direct
{
    /// <summary>
    /// Encryption type for Nostr encrypted messages
    /// </summary>
    public enum NostrEncryptionType
    {
        /// <summary>
        /// NIP-04: Original encryption using AES-256-CBC
        /// </summary>
        Nip04,
        
        /// <summary>
        /// NIP-44 Version 1: ChaCha20 encryption with HMAC-SHA256 (legacy)
        /// </summary>
        Nip44V1,
        
        /// <summary>
        /// NIP-44 Version 2: ChaCha20 encryption with HKDF, padding, and HMAC-SHA256 (recommended)
        /// </summary>
        Nip44V2
    }

    public class NostrEncryptedEvent : NostrEvent
    {
        private const string IvSeparator = "?iv=";

        public NostrEncryptedEvent(string? content, NostrEventTags? tags)
        {
            Content = content;
            TryExtractContent(content);

            Tags = tags;
            RecipientPubkey = tags?.FindFirstTagValue(NostrEventTag.ProfileIdentifier);
        }

        [JsonIgnore]
        public string? EncryptedContent { get; private set; }

        [JsonIgnore]
        public string? InitializationVector { get; private set; }

        [JsonIgnore]
        public string? RecipientPubkey { get; private set; }

        /// <summary>
        /// Decrypt content text by the given private key.
        /// Automatically detects encryption type (NIP-04 or NIP-44).
        /// </summary>
        public string? DecryptContent(NostrPrivateKey privateKey)
        {
            if (EncryptedContent == null)
                throw new InvalidOperationException("Encrypted content is null, can't decrypt");
            if (RecipientPubkey == null)
                throw new InvalidOperationException("Recipient pubkey is not specified, can't decrypt");
            if (Pubkey == null)
                throw new InvalidOperationException("Sender pubkey is not specified, can't decrypt");

            var givenPubkey = privateKey.DerivePublicKey();
            string targetPubkeyHex;
            if (Pubkey == givenPubkey.Hex)
                // given is sender, use recipient pubkey
                targetPubkeyHex = RecipientPubkey;
            else if (RecipientPubkey == givenPubkey.Hex)
                // given is recipient, use sender pubkey
                targetPubkeyHex = Pubkey;
            else
                throw new InvalidOperationException(
                    "The encrypted event is not for the given private key. Sender or receiver pubkey doesn't match");

            var targetPubkey = NostrPublicKey.FromHex(targetPubkeyHex);

            // Detect encryption type
            if (InitializationVector == null)
            {
                // No IV separator found, assume NIP-44 (base64 with version prefix)
                var conversationKey = privateKey.DeriveConversationKeyNip44(targetPubkey);
                return NostrEncryptionNip44.Decrypt(EncryptedContent, conversationKey);
            }
            else
            {
                // IV separator found, use NIP-04
                var sharedKey = privateKey.DeriveSharedKey(targetPubkey);
                var encrypted = new EncryptedBase64Data(EncryptedContent, InitializationVector);
                var decrypted = NostrEncryption.DecryptBase64(encrypted, sharedKey);
                var decryptedText = HashExtensions.ToString(decrypted);
                return decryptedText;
            }
        }

        /// <summary>
        /// Encrypt event, kind will be set to '4 - DirectMessage'.
        /// Uses NIP-04 encryption by default for backward compatibility.
        /// </summary>
        public static NostrEncryptedEvent EncryptDirectMessage(NostrEvent ev, NostrPrivateKey sender, 
            NostrEncryptionType encryptionType = NostrEncryptionType.Nip04)
        {
            return Encrypt(ev, sender, NostrKind.EncryptedDm, encryptionType);
        }

        /// <summary>
        /// Encrypt event, kind will be taken from the given event or can be overriden.
        /// Supports both NIP-04 and NIP-44 encryption.
        /// </summary>
        public static NostrEncryptedEvent Encrypt(NostrEvent ev, NostrPrivateKey sender, NostrKind? kind = null, 
            NostrEncryptionType encryptionType = NostrEncryptionType.Nip04)
        {
            var recipientPubkeyHex = ev.Tags?.FindFirstTagValue(NostrEventTag.ProfileIdentifier);
            if (recipientPubkeyHex == null)
                throw new InvalidOperationException("Recipient pubkey is not specified, can't encrypt");

            var recipientPubkey = NostrPublicKey.FromHex(recipientPubkeyHex);

            string encryptedContent;

            switch (encryptionType)
            {
                case NostrEncryptionType.Nip04:
                    var sharedKeyNip04 = sender.DeriveSharedKey(recipientPubkey);
                    var plainText = HashExtensions.FromString(ev.Content ?? string.Empty);
                    var encrypted = NostrEncryption.EncryptBase64(plainText, sharedKeyNip04);
                    encryptedContent = $"{encrypted.Text}{IvSeparator}{encrypted.Iv}";
                    break;

                case NostrEncryptionType.Nip44V1:
                    var conversationKeyV1 = sender.DeriveConversationKeyNip44(recipientPubkey);
                    encryptedContent = NostrEncryptionNip44.Encrypt(
                        ev.Content ?? string.Empty, 
                        conversationKeyV1, 
                        version: 1);
                    break;

                case NostrEncryptionType.Nip44V2:
                    var conversationKeyV2 = sender.DeriveConversationKeyNip44(recipientPubkey);
                    encryptedContent = NostrEncryptionNip44.Encrypt(
                        ev.Content ?? string.Empty, 
                        conversationKeyV2, 
                        version: 2);
                    break;

                default:
                    throw new ArgumentException($"Unsupported encryption type: {encryptionType}", nameof(encryptionType));
            }

            return new NostrEncryptedEvent(encryptedContent, ev.Tags)
            {
                Kind = kind ?? ev.Kind,
                Pubkey = sender.DerivePublicKey().Hex,
                CreatedAt = ev.CreatedAt,
                Content = encryptedContent
            };
        }

        private void TryExtractContent(string? content)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                EncryptedContent = null;
                InitializationVector = null;
                return;
            }

            var separatorIndex = content.IndexOf(IvSeparator, StringComparison.Ordinal);
            if (separatorIndex == -1)
            {
                // No IV separator found, treat the entire content as encrypted content
                EncryptedContent = content;
                InitializationVector = null;
                return;
            }

            // Extract content before separator and IV after separator
            EncryptedContent = content[..separatorIndex];
            InitializationVector = content[(separatorIndex + IvSeparator.Length)..];
        }
    }
}
