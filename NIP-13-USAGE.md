# NIP-13 Proof of Work Implementation

This library includes a complete implementation of [NIP-13: Proof of Work](https://github.com/nostr-protocol/nips/blob/master/13.md) for Nostr events.

## Features

- ✅ Validate incoming messages with proof-of-work
- ✅ Mine proof-of-work for outgoing messages
- ✅ Count leading zero bits in event IDs
- ✅ Progress reporting during mining
- ✅ Cancellation token support
- ✅ Extension methods on `NostrEvent` for easy usage

## Basic Usage

### Validating Proof of Work (Incoming Messages)

```csharp
using Nostr.Client.Messages;
using Nostr.Client.Utils;

// Receive an event
NostrEvent incomingEvent = /* ... received from relay ... */;

// Validate with minimum difficulty requirement
int minimumDifficulty = 20; // Require at least 20 leading zero bits
bool isValid = incomingEvent.ValidateProofOfWork(minimumDifficulty);

if (isValid)
{
    Console.WriteLine("Event has valid proof of work!");
    Console.WriteLine($"Actual difficulty: {incomingEvent.GetDifficulty()}");
    Console.WriteLine($"Target difficulty: {incomingEvent.GetTargetDifficulty()}");
}
else
{
    Console.WriteLine("Event does not meet minimum proof of work requirements");
}
```

### Mining Proof of Work (Outgoing Messages)

```csharp
using Nostr.Client.Keys;
using Nostr.Client.Messages;

// Create your event
var privateKey = NostrPrivateKey.FromHex("your-private-key-hex");
var publicKey = privateKey.DerivePublicKey();

var event = new NostrEvent
{
    Pubkey = publicKey.Hex,
    CreatedAt = DateTime.UtcNow,
    Kind = NostrKind.ShortTextNote,
    Content = "Hello Nostr with Proof of Work!",
    Tags = NostrEventTags.Empty
};

// Mine proof of work (this will add a "nonce" tag)
int targetDifficulty = 20; // Target 20 leading zero bits
var minedEvent = event.MineProofOfWork(targetDifficulty);

if (minedEvent != null)
{
    // Sign the mined event
    var signedEvent = minedEvent.Sign(privateKey);
    
    // Send to relay
    client.Send(new NostrEventRequest(signedEvent));
}
```

### Mining with Progress Reporting

```csharp
var progressReports = 0;
var minedEvent = event.MineProofOfWork(
    targetDifficulty: 20,
    progressCallback: (nonce, bestDifficulty) =>
    {
        progressReports++;
        Console.WriteLine($"Tried {nonce} nonces, best difficulty so far: {bestDifficulty}");
    },
    progressReportInterval: 10000 // Report every 10,000 iterations
);
```

### Mining with Cancellation Support

```csharp
using var cts = new CancellationTokenSource();

// Cancel after 30 seconds
cts.CancelAfter(TimeSpan.FromSeconds(30));

var minedEvent = event.MineProofOfWork(
    targetDifficulty: 25,
    cancellationToken: cts.Token
);

if (minedEvent == null)
{
    Console.WriteLine("Mining was cancelled or max iterations reached");
}
```

### Mining with Max Iterations Limit

```csharp
// Try up to 1 million iterations
var minedEvent = event.MineProofOfWork(
    targetDifficulty: 20,
    maxIterations: 1_000_000
);

if (minedEvent == null)
{
    Console.WriteLine("Could not find valid proof of work within iteration limit");
}
```

## Static Utility Methods

If you prefer not to use extension methods, you can use the static utility class:

```csharp
using Nostr.Client.Utils;

// Count leading zero bits in a hex string
string eventId = "0000a1b2c3d4...";
int zeroBits = NostrProofOfWork.CountLeadingZeroBits(eventId);

// Validate proof of work
bool isValid = NostrProofOfWork.ValidateProofOfWork(event, minimumDifficulty: 20);

// Get difficulty from event
int difficulty = NostrProofOfWork.GetDifficulty(event);

// Get target difficulty from nonce tag
int target = NostrProofOfWork.GetTargetDifficulty(event);

// Mine proof of work
var mined = NostrProofOfWork.MineProofOfWork(event, targetDifficulty: 20);
```

## Understanding Difficulty Levels

The difficulty is measured in the number of leading zero bits in the event ID hash. Here's a rough guide:

| Difficulty | Average Iterations | Time (approx) | Use Case |
|------------|-------------------|---------------|----------|
| 8          | ~256              | < 1ms         | Testing |
| 16         | ~65,536           | ~10-50ms      | Light protection |
| 20         | ~1,048,576        | ~100-500ms    | Moderate protection |
| 24         | ~16,777,216       | ~2-10s        | Strong protection |
| 28         | ~268,435,456      | ~30s-3min     | Very strong |
| 32         | ~4,294,967,296    | ~10-60min     | Extreme |

**Note:** Times are approximate and depend on hardware and event content.

## NIP-13 Tag Format

The proof of work is stored in a `nonce` tag with the following format:

```json
["nonce", "<nonce_value>", "<target_difficulty>"]
```

For example:
```json
["nonce", "12847", "20"]
```

This indicates:
- The nonce value tried was `12847`
- The target difficulty was `20` leading zero bits
- The resulting event ID must have at least 20 leading zero bits

## Complete Example: Sending a PoW Event

```csharp
using Nostr.Client.Client;
using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.Requests;

// Setup
var privateKey = NostrPrivateKey.FromHex("your-private-key");
var client = new NostrWebsocketClient(communicator, null);

// Create event
var ev = new NostrEvent
{
    Pubkey = privateKey.DerivePublicKey().Hex,
    CreatedAt = DateTime.UtcNow,
    Kind = NostrKind.ShortTextNote,
    Content = "My important message with PoW"
};

// Mine proof of work
Console.WriteLine("Mining proof of work...");
var minedEvent = ev.MineProofOfWork(
    targetDifficulty: 20,
    progressCallback: (nonce, best) => 
    {
        if (nonce % 50000 == 0)
            Console.Write(".");
    },
    progressReportInterval: 50000
);

if (minedEvent == null)
{
    Console.WriteLine("\nMining failed!");
    return;
}

Console.WriteLine($"\nMined! Difficulty: {minedEvent.GetDifficulty()}");

// Sign and send
var signedEvent = minedEvent.Sign(privateKey);
client.Send(new NostrEventRequest(signedEvent));

Console.WriteLine("Event sent with proof of work!");
```

## Validating Relay-Side (Example)

```csharp
// In your relay or bot logic
private bool ValidateIncomingEvent(NostrEvent ev)
{
    const int MINIMUM_DIFFICULTY = 16; // Your relay's requirement
    
    if (!ev.ValidateProofOfWork(MINIMUM_DIFFICULTY))
    {
        Console.WriteLine($"Rejected: insufficient PoW. Required: {MINIMUM_DIFFICULTY}, Got: {ev.GetDifficulty()}");
        return false;
    }
    
    // Other validations (signature, etc.)
    if (!ev.IsSignatureValid())
    {
        Console.WriteLine("Rejected: invalid signature");
        return false;
    }
    
    return true;
}
```

## Performance Tips

1. **Start with lower difficulty**: Test with difficulty 8-16 first, then increase
2. **Use progress callbacks**: Monitor long-running mining operations
3. **Set max iterations**: Prevent infinite loops with very high difficulty
4. **Use cancellation tokens**: Allow users to cancel long operations
5. **Cache mined events**: If sending the same event multiple times, mine once and reuse

## Additional Resources

- [NIP-13 Specification](https://github.com/nostr-protocol/nips/blob/master/13.md)
- [Nostr Protocol Documentation](https://github.com/nostr-protocol/nostr)

