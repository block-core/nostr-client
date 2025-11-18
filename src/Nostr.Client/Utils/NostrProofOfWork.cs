using Nostr.Client.Messages;

namespace Nostr.Client.Utils
{
    /// <summary>
    /// NIP-13: Proof of Work implementation
    /// https://github.com/nostr-protocol/nips/blob/master/13.md
    /// </summary>
    public static class NostrProofOfWork
    {
        public const string NonceTagIdentifier = "nonce";

        /// <summary>
        /// Count the number of leading zero bits in a hex string
        /// </summary>
        /// <param name="hex">Hex string (event ID)</param>
        /// <returns>Number of leading zero bits</returns>
        public static int CountLeadingZeroBits(string? hex)
        {
            if (string.IsNullOrWhiteSpace(hex))
                return 0;

            var bytes = HexExtensions.ToByteArray(hex);
            return CountLeadingZeroBits(bytes);
        }

        /// <summary>
        /// Count the number of leading zero bits in a byte array
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <returns>Number of leading zero bits</returns>
        public static int CountLeadingZeroBits(byte[] bytes)
        {
            var count = 0;
            foreach (var b in bytes)
            {
                if (b == 0)
                {
                    count += 8;
                }
                else
                {
                    // Count leading zeros in this byte
                    var mask = 0x80;
                    for (var i = 0; i < 8; i++)
                    {
                        if ((b & mask) == 0)
                        {
                            count++;
                            mask >>= 1;
                        }
                        else
                        {
                            return count;
                        }
                    }
                }
            }
            return count;
        }

        /// <summary>
        /// Validate proof of work for a Nostr event according to NIP-13
        /// </summary>
        /// <param name="event">Event to validate</param>
        /// <param name="minimumDifficulty">Optional minimum difficulty to enforce (default: 0, meaning any valid nonce tag)</param>
        /// <returns>True if the event has valid proof of work, false otherwise</returns>
        public static bool ValidateProofOfWork(NostrEvent @event, int minimumDifficulty = 0)
        {
            if (@event?.Id == null || @event.Tags == null)
                return minimumDifficulty == 0;

            var nonceTag = @event.Tags.FindFirstTag(NonceTagIdentifier);
            if (nonceTag == null)
                return minimumDifficulty == 0;

            // nonce tag format: ["nonce", "<nonce_value>", "<target_difficulty>"]
            if (nonceTag.AdditionalData.Length < 2)
                return false;

            if (!int.TryParse(nonceTag.AdditionalData[1], out var targetDifficulty))
                return false;

            if (targetDifficulty < minimumDifficulty)
                return false;

            var leadingZeroBits = CountLeadingZeroBits(@event.Id);
            return leadingZeroBits >= targetDifficulty;
        }

        /// <summary>
        /// Get the difficulty (number of leading zero bits) for a Nostr event
        /// </summary>
        /// <param name="event">Event to check</param>
        /// <returns>Number of leading zero bits in the event ID, or 0 if no valid ID</returns>
        public static int GetDifficulty(NostrEvent @event)
        {
            if (@event?.Id == null)
                return 0;

            return CountLeadingZeroBits(@event.Id);
        }

        /// <summary>
        /// Get the target difficulty from the nonce tag
        /// </summary>
        /// <param name="event">Event to check</param>
        /// <returns>Target difficulty from nonce tag, or 0 if no valid nonce tag</returns>
        public static int GetTargetDifficulty(NostrEvent? @event)
        {
            if (@event == null || @event.Tags == null)
                return 0;

            var nonceTag = @event.Tags.FindFirstTag(NonceTagIdentifier);
            if (nonceTag == null || nonceTag.AdditionalData.Length < 2)
                return 0;

            if (!int.TryParse(nonceTag.AdditionalData[1], out var targetDifficulty))
                return 0;

            return targetDifficulty;
        }

        /// <summary>
        /// Mine proof of work for a Nostr event according to NIP-13
        /// This will add/update the nonce tag and return a new event with a valid proof of work
        /// </summary>
        /// <param name="event">Event to mine (will not be modified)</param>
        /// <param name="targetDifficulty">Target number of leading zero bits</param>
        /// <param name="cancellationToken">Optional cancellation token</param>
        /// <param name="maxIterations">Maximum number of iterations before giving up (default: long.MaxValue)</param>
        /// <returns>New event with valid proof of work, or null if mining was cancelled or max iterations reached</returns>
        public static NostrEvent? MineProofOfWork(
            NostrEvent @event,
            int targetDifficulty,
            CancellationToken cancellationToken = default,
            long maxIterations = long.MaxValue)
        {
            return MineProofOfWorkInternal(@event, targetDifficulty, null, 0, cancellationToken, maxIterations);
        }

        /// <summary>
        /// Mine proof of work for a Nostr event with progress reporting
        /// </summary>
        /// <param name="event">Event to mine (will not be modified)</param>
        /// <param name="targetDifficulty">Target number of leading zero bits</param>
        /// <param name="progressCallback">Callback that receives current nonce and best difficulty found so far</param>
        /// <param name="progressReportInterval">Report progress every N iterations (default: 10000)</param>
        /// <param name="cancellationToken">Optional cancellation token</param>
        /// <param name="maxIterations">Maximum number of iterations before giving up (default: long.MaxValue)</param>
        /// <returns>New event with valid proof of work, or null if mining was cancelled or max iterations reached</returns>
        public static NostrEvent? MineProofOfWork(
            NostrEvent @event,
            int targetDifficulty,
            Action<long, int> progressCallback,
            int progressReportInterval = 10000,
            CancellationToken cancellationToken = default,
            long maxIterations = long.MaxValue)
        {
            if (progressCallback == null)
                throw new ArgumentNullException(nameof(progressCallback));

            return MineProofOfWorkInternal(@event, targetDifficulty, progressCallback, progressReportInterval, cancellationToken, maxIterations);
        }

        /// <summary>
        /// Internal mining implementation to avoid code duplication
        /// </summary>
        private static NostrEvent? MineProofOfWorkInternal(
            NostrEvent @event,
            int targetDifficulty,
            Action<long, int>? progressCallback,
            int progressReportInterval,
            CancellationToken cancellationToken,
            long maxIterations)
        {
            if (@event == null)
                throw new ArgumentNullException(nameof(@event));

            if (targetDifficulty < 0)
                throw new ArgumentException("Target difficulty must be non-negative", nameof(targetDifficulty));

            if (targetDifficulty == 0)
            {
                // No work required, just return a clone
                progressCallback?.Invoke(0, 0);
                return @event.DeepClone();
            }

            long nonce = 0;
            var baseTags = @event.Tags ?? NostrEventTags.Empty;
            var bestDifficulty = 0;

            // Remove existing nonce tag if present
            var tagsWithoutNonce = new NostrEventTags(
                baseTags.Where(t => t.TagIdentifier != NonceTagIdentifier)
            );

            while (nonce < maxIterations)
            {
                if (cancellationToken.IsCancellationRequested)
                    return null;

                // Create nonce tag with current nonce value and target difficulty
                var nonceTag = new NostrEventTag(NonceTagIdentifier, nonce.ToString(), targetDifficulty.ToString());
                var tagsWithNonce = tagsWithoutNonce.DeepClone(nonceTag);

                // Create new event with updated tags
                var candidate = @event.DeepClone(null, null, @event.Pubkey, tagsWithNonce);
                var id = candidate.ComputeId();

                // Check if we've met the difficulty target
                var leadingZeroBits = CountLeadingZeroBits(id);
                
                // Track best difficulty for progress reporting
                if (progressCallback != null && leadingZeroBits > bestDifficulty)
                {
                    bestDifficulty = leadingZeroBits;
                }

                // Report progress if callback is provided
                if (progressCallback != null && nonce % progressReportInterval == 0)
                {
                    progressCallback(nonce, bestDifficulty);
                }

                if (leadingZeroBits >= targetDifficulty)
                {
                    // Found valid proof of work!
                    progressCallback?.Invoke(nonce, leadingZeroBits);
                    return candidate.DeepClone(id, null);
                }

                nonce++;
            }

            // Max iterations reached without finding valid proof of work
            return null;
        }
    }
}

