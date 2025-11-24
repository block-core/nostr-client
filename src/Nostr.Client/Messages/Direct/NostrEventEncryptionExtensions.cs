using Nostr.Client.Keys;

namespace Nostr.Client.Messages.Direct
{
    /// <summary>
    /// Extension methods for encrypting NostrEvent objects
    /// </summary>
    public static class NostrEventEncryptionExtensions
    {
        /// <summary>
        /// Encrypt event as a direct message (kind 4) using the specified encryption type.
        /// Default is NIP-04 for backward compatibility.
        /// </summary>
        /// <param name="ev">Event to encrypt</param>
        /// <param name="sender">Sender's private key</param>
        /// <param name="recipientPubkey">Recipient's public key</param>
        /// <param name="encryptionType">Encryption type (NIP-04, NIP-44 v1, or NIP-44 v2)</param>
        /// <returns>Encrypted event with kind set to EncryptedDm (4)</returns>
        public static NostrEncryptedEvent EncryptDirect(this NostrEvent ev, NostrPrivateKey sender, 
            NostrPublicKey recipientPubkey, NostrEncryptionType encryptionType = NostrEncryptionType.Nip04)
        {
            // Add recipient as p tag
            var tags = ev.Tags ?? NostrEventTags.Empty;
            var newTags = new NostrEventTags(tags.Concat(new[] { 
                new NostrEventTag(NostrEventTag.ProfileIdentifier, recipientPubkey.Hex) 
            }));

            var eventWithRecipient = new NostrEvent
            {
                Content = ev.Content,
                CreatedAt = ev.CreatedAt,
                Kind = ev.Kind,
                Tags = newTags
            };

            return NostrEncryptedEvent.EncryptDirectMessage(eventWithRecipient, sender, encryptionType);
        }

        /// <summary>
        /// Encrypt event preserving its kind, using the specified encryption type.
        /// Default is NIP-04 for backward compatibility.
        /// </summary>
        /// <param name="ev">Event to encrypt</param>
        /// <param name="sender">Sender's private key</param>
        /// <param name="recipientPubkey">Recipient's public key</param>
        /// <param name="encryptionType">Encryption type (NIP-04, NIP-44 v1, or NIP-44 v2)</param>
        /// <returns>Encrypted event with original kind preserved</returns>
        public static NostrEncryptedEvent Encrypt(this NostrEvent ev, NostrPrivateKey sender, 
            NostrPublicKey recipientPubkey, NostrEncryptionType encryptionType = NostrEncryptionType.Nip04)
        {
            // Add recipient as p tag
            var tags = ev.Tags ?? NostrEventTags.Empty;
            var newTags = new NostrEventTags(tags.Concat(new[] { 
                new NostrEventTag(NostrEventTag.ProfileIdentifier, recipientPubkey.Hex) 
            }));

            var eventWithRecipient = new NostrEvent
            {
                Content = ev.Content,
                CreatedAt = ev.CreatedAt,
                Kind = ev.Kind,
                Tags = newTags
            };

            return NostrEncryptedEvent.Encrypt(eventWithRecipient, sender, ev.Kind, encryptionType);
        }
    }
}

