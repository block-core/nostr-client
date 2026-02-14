using System.Reactive.Linq;
using System.Reactive.Subjects;
using Nostr.Client.Responses;

namespace Nostr.Client.Client
{
    public class NostrClientStreams
    {
        internal readonly Subject<NostrEventResponse> EventSubject = new();
        internal readonly Subject<NostrNoticeResponse> NoticeSubject = new();
        internal readonly Subject<NostrEoseResponse> EoseSubject = new();
        internal readonly Subject<NostrOkResponse> OkSubject = new();

        internal readonly Subject<NostrResponse> UnknownMessageSubject = new();
        internal readonly Subject<NostrRawResponse> UnknownRawSubject = new();

        /// <summary>
        /// Requested Nostr events (includes all events, signature not validated)
        /// </summary>
        public IObservable<NostrEventResponse> EventStream => EventSubject.AsObservable();

        /// <summary>
        /// Requested Nostr events with valid signatures only.
        /// Events with invalid or missing signatures are filtered out.
        /// </summary>
        public IObservable<NostrEventResponse> ValidEventStream => EventSubject
            .AsObservable()
            .Where(x => x.IsSignatureValid);

        /// <summary>
        /// Human-readable messages
        /// </summary>
        public IObservable<NostrNoticeResponse> NoticeStream => NoticeSubject.AsObservable();

        /// <summary>
        /// Information that all stored events have been sent out
        /// </summary>
        public IObservable<NostrEoseResponse> EoseStream => EoseSubject.AsObservable();

        /// <summary>
        /// Information if the sent event was accepted or rejected
        /// </summary>
        public IObservable<NostrOkResponse> OkStream => OkSubject.AsObservable();

        /// <summary>
        /// Unknown and unhandled messages
        /// </summary>
        public IObservable<NostrResponse> UnknownMessageStream => UnknownMessageSubject.AsObservable();

        /// <summary>
        /// Unknown messages that are not even in the parseable format
        /// </summary>
        public IObservable<NostrRawResponse> UnknownRawStream => UnknownRawSubject.AsObservable();

    }
}
