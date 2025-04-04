﻿using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Nostr.Client.Messages;
using System.Collections.Generic;

namespace Nostr.Client.Requests
{
    public class NostrFilter
    {
        /// <summary>
        /// A list of event ids or prefixes
        /// </summary>
        public string[]? Ids { get; set; }

        /// <summary>
        /// A list of pubkeys or prefixes, the pubkey of an event must be one of these
        /// </summary>
        public string[]? Authors { get; set; }

        /// <summary>
        /// A list of a kind numbers
        /// </summary>
        public NostrKind[]? Kinds { get; set; }

        /// <summary>
        /// A list of event ids that are referenced in an "e" tag
        /// </summary>
        [JsonProperty("#e")]
        public string[]? E { get; set; }

        /// <summary>
        /// A list of pubkeys that are referenced in a "p" tag
        /// </summary>
        [JsonProperty("#p")]
        public string[]? P { get; set; }

        /// <summary>
        /// A list of coordinates to events in an "a" tag
        /// </summary>
        [JsonProperty("#a")]
        public string[]? A { get; set; }

        /// <summary>
        /// A list of subject tags to filter by (NIP-14)
        /// </summary>
        [JsonProperty("#subject")]
        public string[]? Subject { get; set; }

        /// <summary>
        /// Events must be newer than this to pass
        /// </summary>
        public DateTime? Since { get; set; }

        /// <summary>
        /// Events must be older than this to pass
        /// </summary>
        public DateTime? Until { get; set; }

        /// <summary>
        /// Maximum number of events to be returned in the initial query
        /// </summary>
        public int? Limit { get; set; }

        private readonly Dictionary<string, JToken> _tags = new();

        /// <summary>
        /// Gets all custom tag filters
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JToken> Tags => _tags;

        /// <summary>
        /// Adds a custom tag filter
        /// </summary>
        /// <param name="tagName">Tag name without the '#' prefix</param>
        /// <param name="values">Values to filter by</param>
        public void AddTag(string tagName, params string[] values)
        {
            if (string.IsNullOrWhiteSpace(tagName))
                throw new ArgumentNullException(nameof(tagName), "Tag name cannot be null, empty or whitespace.");

            _tags[$"#{tagName.Trim()}"] = JArray.FromObject(values);
        }

        /// <summary>
        /// Removes a custom tag filter
        /// </summary>
        /// <param name="tagName">Tag name without the '#' prefix</param>
        public bool RemoveTag(string tagName)
        {
            if (string.IsNullOrEmpty(tagName))
                return false;

            return _tags.Remove($"#{tagName}");
        }
    }
}
