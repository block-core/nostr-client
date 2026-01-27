# Agent Development Guide

This document provides essential information for AI coding agents working in the Nostr.Client repository.

## Project Overview

**Nostr.Client** is a C# implementation of the Nostr protocol (websocket-based decentralized social protocol). The codebase targets .NET 6.0+ and uses reactive extensions (Rx.NET) for real-time event streaming.

## Repository Structure

```
src/Nostr.Client/          # Main library (targeting net6.0 and net7.0)
  ├── Client/              # Client implementations (NostrWebsocketClient, NostrMultiWebsocketClient)
  ├── Communicator/        # Communication layer (WebSocket, File-based for testing)
  ├── Messages/            # Event models and message types
  ├── Requests/            # Request models (Event, Filter, Close)
  ├── Responses/           # Response models (Event, Notice, OK, EOSE)
  ├── Keys/                # Cryptographic key handling (Public, Private, KeyPair)
  ├── Utils/               # Utilities (Encryption, Proof of Work, Converters)
  ├── Json/                # Custom JSON serialization
  └── Identifiers/         # NIP-19 bech32-encoded entity parsing

test/Nostr.Client.Tests/           # Unit tests (xUnit)
test_integration/                  # Integration tests and sample console app
apps/                             # Demo applications (nostr-debug, nostr-bot, smart-relay)
```

## Build, Test, and Run Commands

### Build
```bash
# Restore dependencies
dotnet restore

# Build entire solution
dotnet build

# Build in Release mode
dotnet build --configuration Release
```

### Test
```bash
# Run all tests
dotnet test

# Run tests with verbosity
dotnet test --verbosity normal

# Run a single test
dotnet test --filter "FullyQualifiedName~NostrClientTests.SimpleEvent_ShouldBeCorrectlySerialized"

# Run all tests in a class
dotnet test --filter "FullyQualifiedName~NostrClientTests"

# Run tests by name pattern
dotnet test --filter "DisplayName~Nip44"
```

### Pack and Publish
```bash
# Create NuGet package
dotnet pack src/Nostr.Client/Nostr.Client.csproj --configuration Release

# Pack with symbols
dotnet pack src/Nostr.Client/Nostr.Client.csproj --configuration Release --include-symbols -p:SymbolPackageFormat=snupkg
```

### Run Sample/Integration Apps
```bash
# Run console sample
dotnet run --project test_integration/Nostr.Client.Sample.Console/Nostr.Client.Sample.Console.csproj

# Run NostrDebug Blazor app
dotnet run --project apps/nostr-debug/NostrDebug.Web/NostrDebug.Web.csproj

# Run NostrBot
dotnet run --project apps/nostr-bot/NostrBot.Web/NostrBot.Web.csproj
```

## Code Style Guidelines

### General Principles
- **Warnings as Errors**: `TreatWarningsAsErrors` is set to `True` in the main library. Code MUST compile without warnings.
- **Nullable Reference Types**: Enabled (`<Nullable>enable</Nullable>`). Use nullable annotations appropriately.
- **XML Documentation**: Generate documentation files. Public APIs should have XML doc comments.

### Naming Conventions
- **Classes/Interfaces**: PascalCase (e.g., `NostrWebsocketClient`, `INostrCommunicator`)
- **Methods**: PascalCase (e.g., `HandleMessage`, `DeserializeRaw`)
- **Properties**: PascalCase (e.g., `CreatedAt`, `MessageReceived`)
- **Private Fields**: Camelback with underscore prefix (e.g., `_logger`, `_messageReceivedSubscription`)
- **Local Variables**: camelCase (e.g., `communicator`, `serialized`)
- **Constants**: PascalCase per ReSharper settings (e.g., `NostrMessageTypes.Event`)
- **Parameters**: camelCase (e.g., `request`, `message`)

### Formatting (from .editorconfig)
- **Indentation**: 4 spaces for C# files (`indent_style = space`, `indent_size = 4`)
- **Tabs**: Used for XML/config files like .csproj
- **Line Endings**: Controlled by `.gitattributes` (CRLF on Windows, LF on Unix)
- **No trailing whitespace**

### C# Style Preferences
- **`var` usage**: Prefer `var` everywhere (built-in types, apparent types, elsewhere)
  ```csharp
  var logger = new NullLogger<NostrWebsocketClient>();
  var serialized = JsonConvert.SerializeObject(request, _jsonSettings);
  ```
- **Modifiers order**: `public, private, protected, internal, file, new, static, abstract, virtual, sealed, readonly, override, extern, unsafe, volatile, async, required`
- **No `this.` qualifier**: Don't use `this.` for fields, properties, methods, or events
- **Built-in type names**: Use `string`, `int`, etc. instead of `String`, `Int32`
- **Parentheses**: Minimal in arithmetic/relational operators, required for clarity in other binary operators

### File Organization
- **One class per file** (with rare exceptions for tightly coupled types)
- **Namespace matches folder structure**: `namespace Nostr.Client.Messages` for files in `Messages/`
- **Using directives**: Place at top of file, outside namespace
  ```csharp
  using System;
  using Newtonsoft.Json;
  using Nostr.Client.Messages;
  
  namespace Nostr.Client.Client
  {
      // class implementation
  }
  ```

### Error Handling
- **Validate arguments**: Check for null and throw `ArgumentNullException` early
  ```csharp
  if (request == null)
  {
      throw new ArgumentNullException(nameof(request));
  }
  ```
- **Log and rethrow**: Log exceptions with context, then rethrow
  ```csharp
  catch (Exception e)
  {
      _logger.LogError(e, "Exception while sending message '{request}'", request);
      throw;
  }
  ```
- **Use `??` and `??throw`**: For null-coalescing with exceptions
  ```csharp
  var deserialized = JsonConvert.DeserializeObject<T>(content, _jsonSettings) ??
      throw new InvalidOperationException("Deserialized message is null, cannot continue");
  ```

### Dependency Injection
- Use constructor injection for dependencies
- Accept `ILogger<T>?` and default to `NullLogger<T>` if null
  ```csharp
  public NostrWebsocketClient(INostrCommunicator communicator, ILogger<NostrWebsocketClient>? logger)
  {
      _logger = logger ?? new NullLogger<NostrWebsocketClient>();
      Communicator = communicator;
  }
  ```

### Asynchronous Code
- Follow async/await patterns for I/O operations
- Use `Task` and `Task<T>` return types for async methods
- Name async methods with `Async` suffix when appropriate

### Testing
- **Framework**: xUnit
- **Naming**: Test method names should describe the scenario: `MethodName_Scenario_ExpectedBehavior`
  ```csharp
  [Fact]
  public void SimpleEvent_ShouldBeCorrectlySerialized()
  ```
- **Fakes over Mocks**: Use hand-written fakes (e.g., `NostrFakeCommunicator`) instead of mocking frameworks
- **Arrange-Act-Assert**: Structure tests clearly
- **Test Data**: Use specific, realistic data (real hashes, keys from test vectors)

### JSON Serialization
- Use **Newtonsoft.Json** (not System.Text.Json)
- Custom converters in `Json/` folder for specialized types
- Cache `JsonSerializerSettings` to avoid repeated instantiation
- Property names use snake_case when serialized: `created_at`, `pubkey`

### Comments and Documentation
- **XML comments** for all public APIs
  ```csharp
  /// <summary>
  /// Serializes request and sends message via websocket communicator. 
  /// It logs and re-throws every exception. 
  /// </summary>
  /// <param name="request">Request/message to be sent</param>
  public void Send<T>(T request)
  ```
- **Inline comments**: Use sparingly, prefer self-documenting code
- **Comment complex logic**: Explain "why", not "what"

## Important Patterns

### Reactive Extensions (Rx.NET)
- Events are exposed via `IObservable<T>` streams
- Subscribe to streams using `.Subscribe(handler)`
- Dispose subscriptions properly

### Immutability
- Most event models use `init` accessors (immutable after construction)
- For mutable scenarios, separate "Mutable" types exist in `Messages/Mutable/`

### Extensibility
- Use interfaces for abstractions (`INostrCommunicator`, `INostrClient`)
- Support custom implementations (e.g., `NostrFileCommunicator` for testing)

## Common Pitfalls

1. **Don't forget to call `Start()`** on communicators before use
2. **Resubscribe after reconnection** - subscriptions don't persist across reconnects
3. **Handle additional data** - Events may have unparsed fields in `AdditionalData`
4. **DateTime handling** - Use `DateTime.UtcNow` and `DateTimeKind.Utc` for event timestamps
5. **Hex encoding** - All IDs, keys, and signatures are lowercase hex-encoded

## Resources

- **NIP Coverage**: See README.md for implemented Nostr Improvement Proposals
- **Sample Code**: Check `test_integration/Nostr.Client.Sample.Console/Program.cs`
- **Test Vectors**: `nip44.vectors.json` for NIP-44 encryption validation
- **Documentation**: Implementation summaries in `NIP44_IMPLEMENTATION.md`, `NIP-13-IMPLEMENTATION-SUMMARY.md`

## NuGet Package

- **Package ID**: `Blockcore.Nostr.Client`
- **Assembly**: `Blockcore.Nostr.Client.dll`
- **License**: Apache-2.0
