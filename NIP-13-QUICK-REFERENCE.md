# NIP-13 Quick Reference

## Quick Start

### Validate Incoming Message
```csharp
if (event.ValidateProofOfWork(minimumDifficulty: 20))
{
    // Process the event
}
```

### Create Message with PoW
```csharp
var mined = event.MineProofOfWork(targetDifficulty: 20);
var signed = mined?.Sign(privateKey);
client.Send(new NostrEventRequest(signed));
```

## Key Methods

| Method | Purpose | Returns |
|--------|---------|---------|
| `ValidateProofOfWork(int min)` | Check if event meets min difficulty | bool |
| `GetDifficulty()` | Get actual leading zero bits | int |
| `GetTargetDifficulty()` | Get target from nonce tag | int |
| `MineProofOfWork(int target)` | Mine PoW for event | NostrEvent? |

## Difficulty Recommendations

| Level | Bits | Time | Use Case |
|-------|------|------|----------|
| Low | 16 | ~50ms | Testing, light spam prevention |
| Medium | 20 | ~500ms | General use, moderate protection |
| High | 24 | ~5s | Important events, strong protection |
| Very High | 28+ | ~1min+ | Critical events, maximum protection |

## Common Patterns

### Pattern 1: Validate with fallback
```csharp
const int REQUIRED_DIFFICULTY = 20;
if (!event.ValidateProofOfWork(REQUIRED_DIFFICULTY))
{
    logger.Warning($"Event {event.Id} rejected: insufficient PoW");
    return false;
}
```

### Pattern 2: Mine with timeout
```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
var mined = event.MineProofOfWork(20, cancellationToken: cts.Token);
if (mined == null)
{
    logger.Error("Mining timeout or failed");
}
```

### Pattern 3: Mine with progress
```csharp
var mined = event.MineProofOfWork(
    targetDifficulty: 20,
    progressCallback: (n, d) => Console.Write("."),
    progressReportInterval: 10000
);
```

### Pattern 4: Check difficulty info
```csharp
Console.WriteLine($"Event difficulty: {event.GetDifficulty()}");
Console.WriteLine($"Target difficulty: {event.GetTargetDifficulty()}");
Console.WriteLine($"Valid: {event.ValidateProofOfWork(16)}");
```

## Implementation Notes

- Mining adds a `["nonce", "<value>", "<target>"]` tag to the event
- Original event is not modified (returns new instance)
- All existing tags are preserved during mining
- Event must be signed AFTER mining (to include the nonce tag in signature)

## See Also

- `NIP-13-USAGE.md` - Detailed usage documentation
- `NIP-13-IMPLEMENTATION-SUMMARY.md` - Technical implementation details
- [NIP-13 Spec](https://github.com/nostr-protocol/nips/blob/master/13.md)

