using Nostr.Client.Messages;
using System.Threading;
using System.Threading.Tasks;

namespace Nostr.Client.NostrPow.Mining
{
    /// <summary>
    /// Interface for Nostr event miners
    /// </summary>
    public interface IMiner
    {
        /// <summary>
        /// Mine an event to generate proof of work
        /// </summary>
        /// <param name="originalEvent">The event to mine</param>
        /// <param name="difficulty">Target difficulty in bits</param>
        /// <param name="cancellationToken">Cancellation token to stop mining</param>
        /// <returns>A new event with the proof of work</returns>
        Task<NostrEvent> MineEventAsync(NostrEvent originalEvent, int difficulty, CancellationToken cancellationToken = default);
    }
}
