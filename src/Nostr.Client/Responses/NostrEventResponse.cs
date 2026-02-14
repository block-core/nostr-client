using System.Diagnostics;
using Newtonsoft.Json;
using Nostr.Client.Json;
using Nostr.Client.Messages;

namespace Nostr.Client.Responses
{
    [DebuggerDisplay("[{CommunicatorName}] {MessageType} - {Subscription}")]
    public class NostrEventResponse : NostrResponse
    {
        [ArrayProperty(1)]
        public string? Subscription { get; init; }

        [ArrayProperty(2)]
        [JsonConverter(typeof(NostrEventConverter))]
        public NostrEvent? Event { get; init; }

        /// <summary>
        /// Check if the event signature is valid.
        /// Returns false if event is null or signature verification fails.
        /// </summary>
        [JsonIgnore]
        public bool IsSignatureValid => Event?.IsSignatureValid() ?? false;
    }
}
