![Logo](https://raw.githubusercontent.com/Marfusios/nostr-client/master/nostr.png)
# Nostr client 
[![.NET Core](https://github.com/Marfusios/nostr-client/actions/workflows/dotnet-core.yml/badge.svg)](https://github.com/Marfusios/nostr-client/actions/workflows/dotnet-core.yml) [![NuGet version](https://badge.fury.io/nu/Nostr.Client.svg)](https://badge.fury.io/nu/Nostr.Client) [![NuGet downloads](https://img.shields.io/nuget/dt/Nostr.Client)](https://www.nuget.org/packages/Nostr.Client)

This is a C# implementation of the Nostr protocol found here:

https://github.com/nostr-protocol/nips

Nostr protocol is based on websocket communication. 
This library keeps a reliable connection to get real-time data and fast execution of your commands. 

[Releases and breaking changes](https://github.com/Marfusios/nostr-client/releases)

### License: 
    Apache License 2.0

### Features

* installation via NuGet ([Nostr.Client](https://www.nuget.org/packages/Nostr.Client))
* targeting .NET 6.0 and higher (.NET Core, Linux/MacOS compatible)
* reactive extensions ([Rx.NET](https://github.com/Reactive-Extensions/Rx.NET))

### Usage

#### Receiving events

```csharp
var url = new Uri("wss://relay.damus.io");

using var communicator = new NostrWebsocketCommunicator(url);
using var client = new NostrWebsocketClient(communicator, null);

client.Streams.EventStream.Subscribe(response =>
{
    var ev = response.Event;
    Log.Information("{kind}: {content}", ev?.Kind, ev?.Content)
            
    if(ev is NostrMetadataEvent evm) {
        Log.Information("Name: {name}, about: {about}", evm.Metadata?.Name, evm.Metadata?.About);
    }
});

await communicator.Start();
```

#### Sending event

```csharp
var ev = new NostrEvent
{
    Kind = NostrKind.ShortTextNote,
    CreatedAt = DateTime.UtcNow,
    Content = "Test message from C# client"
};

var key = NostrPrivateKey.FromBech32("nsec1xxx");
var signed = ev.Sign(key);

client.Send(new NostrEventRequest(signed));
```

#### Sending encrypted direct message (NIP-04)

```csharp
var sender = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
var receiver = NostrPublicKey.FromBech32("npub1dd668dyr9un9nzf9fjjkpdcqmge584c86gceu7j97nsp4lj2pscs0xk075");

var ev = new NostrEvent
{
    CreatedAt = DateTime.UtcNow,
    Content = $"Test private message from C# client"
};

var encrypted = ev.EncryptDirect(sender, receiver);
var signed = encrypted.Sign(sender);

client.Send(new NostrEventRequest(signed));
```

#### Multi relays support

```csharp
var relays = new[]
{
    new NostrWebsocketCommunicator(new Uri("wss://relay.snort.social")),
    new NostrWebsocketCommunicator(new Uri("wss://relay.damus.io")),
    new NostrWebsocketCommunicator(new Uri("wss://nos.lol"))
};

var client = new NostrMultiWebsocketClient(NullLogger<NostrWebsocketClient>.Instance, relays);

client.Streams.EventStream.Subscribe(HandleEvent);

relays.ToList().ForEach(relay => relay.Start());
```

More usage examples:
* Tests ([link](tests/Nostr.Client.Tests))
* Console sample ([link](test_integration/Nostr.Client.Sample.Console/Program.cs))
* NostrDebug - Blazor app ([link](apps/nostr-debug/NostrDebug.Web), [deployed](https://nostrdebug.com))

![image](https://raw.githubusercontent.com/Marfusios/nostr-client/master/apps/nostr-debug/NostrDebug.Web/wwwroot/nostr-preview.png)

### NIP's coverage

- [x] NIP-01: Basic protocol flow description
- [x] NIP-02: Contact List and Petnames (No petname support)
- [ ] NIP-03: OpenTimestamps Attestations for Events
- [x] NIP-04: Encrypted Direct Message
- [ ] NIP-05: Mapping Nostr keys to DNS-based internet identifiers
- [ ] NIP-06: Basic key derivation from mnemonic seed phrase
- [ ] NIP-07: `window.nostr` capability for web browsers
- [ ] NIP-08: Handling Mentions
- [ ] NIP-09: Event Deletion
- [ ] NIP-10: Conventions for clients' use of `e` and `p` tags in text events
- [ ] NIP-11: Relay Information Document
- [ ] NIP-12: Generic Tag Queries
- [x] NIP-13: Proof of Work
- [x] NIP-14: Subject tag in text events
- [x] NIP-15: End of Stored Events Notice
- [x] NIP-19: bech32-encoded entities
- [x] NIP-20: Command Results
- [ ] NIP-21: `nostr:` Protocol handler (`web+nostr`)
- [ ] NIP-25: Reactions
- [ ] NIP-26: Delegated Event Signing (Display delegated signings only)
- [ ] NIP-28: Public Chat
- [ ] NIP-36: Sensitive Content
- [ ] NIP-40: Expiration Timestamp
- [ ] NIP-42: Authentication of clients to relays
- [ ] NIP-50: Search
- [ ] NIP-51: Lists
- [ ] NIP-65: Relay List Metadata

**Pull Requests are welcome!**

#### Proof of Work (NIP-13)

Proof of Work in Nostr allows clients to demonstrate computational effort spent on creating an event. This can be used for spam reduction by requiring events to have a minimum difficulty level.

##### Basic Usage

```csharp
// Create an event
var ev = new NostrEvent
{
    Kind = NostrKind.ShortTextNote,
    CreatedAt = DateTime.UtcNow,
    Content = "This message includes proof of work to demonstrate NIP-13"
};

// Mine the event with difficulty 16 (leading zero bits)
var minedEvent = await ev.GeneratePow(16);

// Once mined, sign it with your private key
var key = NostrPrivateKey.FromBech32("nsec1xxx");
var signedMinedEvent = minedEvent.Sign(key);

// Check the actual difficulty achieved
int difficulty = signedMinedEvent.GetDifficulty();
Console.WriteLine($"Event ID: {signedMinedEvent.Id}");
Console.WriteLine($"Difficulty achieved: {difficulty} bits");

// Send to relay
client.Send(new NostrEventRequest(signedMinedEvent));
```

##### Validating Proof of Work

When receiving an event, you can verify if it meets a minimum difficulty requirement:

```csharp
// Check if an event has a valid PoW with a difficulty of at least 15 bits
int minDifficulty = 15;
bool isValid = receivedEvent.HasValidPow(minDifficulty);
if (isValid)
{
    Console.WriteLine($"Event has valid PoW with difficulty: {receivedEvent.GetDifficulty()} bits");
}
else
{
    Console.WriteLine("Event does not have sufficient proof of work");
}
```

##### Advanced: Using Delegate-based Mining for Progress Updates

For longer mining operations, you may want to receive progress updates and have more control over the mining process. The library provides a delegate-based approach for this:

```csharp
// Define delegate handlers for progress and completion
void OnProgress(string currentNonce, int difficulty, long attemptsCount)
{
    Console.WriteLine($"Mining in progress - Current nonce: {currentNonce}, " +
                      $"Current difficulty: {difficulty}, Attempts: {attemptsCount}");
}

void OnComplete(bool success, string nonce, int difficulty, long totalAttempts, long elapsedMs)
{
    if (success)
    {
        Console.WriteLine($"Mining successful! Found nonce: {nonce}");
        Console.WriteLine($"Difficulty achieved: {difficulty} bits");
        Console.WriteLine($"Total attempts: {totalAttempts:N0} in {elapsedMs}ms");
        Console.WriteLine($"Hash rate: {totalAttempts * 1000 / elapsedMs} hashes/second");
    }
    else
    {
        Console.WriteLine($"Mining was cancelled or failed after {totalAttempts:N0} attempts");
    }
}

// Create and configure a PoW calculator
var calculator = new PowCalculator();
calculator.OnProgress += OnProgress;  // Subscribe to progress updates
calculator.OnCompletion += OnComplete;  // Subscribe to completion notification

try
{
    // Start PoW calculation with target difficulty and specified nonce size (in bytes)
    string eventId = myEvent.ComputeId();  // First compute the event ID
    await calculator.StartCalculation(eventId, 20, 4);  // Target 20 bits, 4-byte nonce
    
    // The mining happens on a background thread, your UI remains responsive
    
    // If you need to cancel the calculation:
    // calculator.CancelCalculation();
}
catch (Exception ex)
{
    Console.WriteLine($"Error in PoW calculation: {ex.Message}");
}
finally
{
    // Important: Unsubscribe when done to prevent memory leaks
    calculator.OnProgress -= OnProgress;
    calculator.OnCompletion -= OnComplete;
}
```

##### Manual Mining with Low-level API

For more control over the mining process, you can use the lower-level `EventMiner` class directly:

```csharp
// Create a new event
var originalEvent = new NostrEvent
{
    Kind = NostrKind.ShortTextNote,
    CreatedAt = DateTime.UtcNow,
    Content = "Mining with low-level API"
};

// Set up cancellation (optional, for timeout)
using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));

try
{
    // Mine the event directly using the EventMiner
    var minedEvent = await EventMiner.MineEventAsync(originalEvent, 16, cts.Token);
    
    Console.WriteLine($"Mining successful! Event ID: {minedEvent.Id}");
    Console.WriteLine($"Difficulty: {minedEvent.GetDifficulty()} bits");
    
    // Find the nonce used
    var nonceTag = minedEvent.Tags?.FindFirstTag("nonce");
    if (nonceTag != null)
    {
        Console.WriteLine($"Nonce: {nonceTag.AdditionalData[0]}");
        Console.WriteLine($"Target difficulty: {nonceTag.AdditionalData[1]}");
    }
    
    // Send the event to a relay
    client.Send(new NostrEventRequest(minedEvent));
}
catch (OperationCanceledException)
{
    Console.WriteLine("Mining was cancelled or timed out");
}
```

### Reconnecting

A built-in reconnection invokes after 1 minute (default) of not receiving any messages from the server. 
It is possible to configure that timeout via `communicator.ReconnectTimeout`. 
Also, a stream `ReconnectionHappened` sends information about a type of reconnection. 
However, if you are subscribed to low-rate channels, you will likely encounter that timeout - higher it to a few minutes or implement `ping-pong` interaction on your own every few seconds. 

In the case of Nostr relay outage, there is a built-in functionality that slows down reconnection requests 
(could be configured via `client.ErrorReconnectTimeout`, the default is 1 minute).

Beware that you **need to resubscribe to channels** after reconnection happens. You should subscribe to `ReconnectionHappened` stream and send subscription requests. 

### Testing

The library is prepared for replay testing. The dependency between `Client` and `Communicator` is via abstraction `INostrCommunicator`. There are two communicator implementations: 
* `NostrWebsocketCommunicator` - real-time communication with Nostr relay.
* `NostrFileCommunicator` - a simulated communication, raw data are loaded from files and streamed.

Feel free to implement `INostrCommunicator` on your own, for example, load raw data from database, cache, etc. 

Usage: 

```csharp
var communicator = new NostrFileCommunicator();
communicator.FileNames = new[]
{
    "data/nostr-data.txt"
};
communicator.Delimiter = "\n";

var client = new NostrWebsocketClient(communicator);
client.Streams.EventStream.Subscribe(trade =>
{
    // do something with an event
});

await communicator.Start();
```

### Multi-threading and other considerations

See [Websocket Client readme](https://github.com/Marfusios/websocket-client#multi-threading)
