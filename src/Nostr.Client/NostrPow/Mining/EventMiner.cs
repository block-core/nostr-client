using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Nostr.Client.Messages;

namespace Nostr.Client.NostrPow.Mining
{
    /// <summary>
    /// Provides methods for mining Nostr events (adding proof of work)
    /// </summary>
    public static class EventMiner
    {
        private static readonly Random Random = new Random();

        /// <summary>
        /// Mine an event to generate proof of work with the specified difficulty
        /// </summary>
        /// <param name="originalEvent">The event to mine</param>
        /// <param name="difficulty">Target difficulty in bits</param>
        /// <param name="cancellationToken">Cancellation token to stop mining</param>
        /// <returns>A new event with the proof of work</returns>
        public static async Task<NostrEvent> MineEventAsync(NostrEvent originalEvent, int difficulty, CancellationToken cancellationToken = default)
        {
            // Create a cloned event for mining
            var tags = originalEvent.Tags ?? new NostrEventTags();
            
            // Find the existing nonce tag if any
            NostrEventTag? nonceTag = tags.FindFirstTag("nonce");
            int nonceIndex = -1;
            
            if (nonceTag != null)
            {
                // Find the index of the nonce tag
                for (int i = 0; i < tags.Count; i++)
                {
                    if (tags[i].TagIdentifier == "nonce")
                    {
                        nonceIndex = i;
                        break;
                    }
                }
            }

            // Start with a random nonce
            long nonce = Random.Next(0, int.MaxValue);

            // Create a new mutable copy of the tags
            var newTags = new List<NostrEventTag>();
            for (int i = 0; i < tags.Count; i++)
            {
                // Skip the existing nonce tag, we'll add a new one
                if (i != nonceIndex)
                {
                    newTags.Add(tags[i].DeepClone());
                }
            }
            
            // We'll add the nonce tag at the end
            NostrEventTag newNonceTag = new NostrEventTag("nonce", nonce.ToString(), difficulty.ToString());
            newTags.Add(newNonceTag);
            
            // Create the event to mine with initial tags
            var eventToMine = originalEvent.DeepClone(null, null, originalEvent.Pubkey, new NostrEventTags(newTags));
            
            // Update timestamp to current time, common practice in mining
            var miningEvent = eventToMine.DeepClone();
            miningEvent = miningEvent.DeepClone(null, null, miningEvent.Pubkey, miningEvent.Tags);
            // Set a current timestamp
            miningEvent = new NostrEvent
            {
                Id = miningEvent.Id,
                Pubkey = miningEvent.Pubkey,
                CreatedAt = DateTime.UtcNow, // Update timestamp
                Kind = miningEvent.Kind,
                Tags = miningEvent.Tags,
                Content = miningEvent.Content,
                Sig = miningEvent.Sig
            };

            return await Task.Run(() =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    // Update the nonce in the tag
                    var updatedTags = new List<NostrEventTag>();
                    for (int i = 0; i < miningEvent.Tags!.Count; i++)
                    {
                        var tag = miningEvent.Tags[i];
                        if (tag.TagIdentifier == "nonce")
                        {
                            // Update the nonce value
                            updatedTags.Add(new NostrEventTag("nonce", nonce.ToString(), difficulty.ToString()));
                        }
                        else
                        {
                            updatedTags.Add(tag.DeepClone());
                        }
                    }

                    // Create a new event with the updated nonce
                    var candidateEvent = miningEvent.DeepClone(
                        null,
                        miningEvent.Sig,
                        miningEvent.Pubkey,
                        new NostrEventTags(updatedTags));

                    // Compute the ID and check if it meets the difficulty requirement
                    string id = candidateEvent.ComputeId();
                    int achievedDifficulty = DifficultyCalculator.CountLeadingZeroBits(id);
                    
                    if (achievedDifficulty >= difficulty)
                    {
                        // We found a valid nonce, return the mined event
                        return candidateEvent.DeepClone(id, candidateEvent.Sig);
                    }

                    // Increment nonce and try again
                    nonce++;
                }

                // Mining was canceled
                throw new OperationCanceledException("Mining was canceled");
            }, cancellationToken);
        }
    }
}
