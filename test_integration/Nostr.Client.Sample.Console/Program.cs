using System;
using System.Net.WebSockets;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using Microsoft.Extensions.Logging;
using Nostr.Client.Client;
using Nostr.Client.Communicator;
using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.Requests;
using Nostr.Client.Sample.Console;
using Serilog;
using Serilog.Events;
using Serilog.Extensions.Logging;
using Serilog.Sinks.SystemConsole.Themes;

var exitEvent = new ManualResetEvent(false);

var logFactory = InitLogging();

AppDomain.CurrentDomain.ProcessExit += CurrentDomainOnProcessExit;
AssemblyLoadContext.Default.Unloading += DefaultOnUnloading;
Console.CancelKeyPress += ConsoleOnCancelKeyPress;

Console.WriteLine("|======================|");
Console.WriteLine("|     NOSTR CLIENT     |");
Console.WriteLine("|======================|");
Console.WriteLine();

Log.Debug("====================================");
Log.Debug("              STARTING              ");
Log.Debug("====================================");

var relays = new[]
{
    new Uri("wss://relay.snort.social"),
    new Uri("wss://relay.damus.io"),
    new Uri("wss://eden.nostr.land"),
    new Uri("wss://nostr-pub.wellorder.net"),
    new Uri("wss://nos.lol"),
};

// Example of mining a Nostr event with proof of work
await MineAndSendProofOfWorkExample(relays);

using var multiClient = new NostrMultiWebsocketClient(logFactory.CreateLogger<NostrWebsocketClient>());
var communicators = new List<NostrWebsocketCommunicator>();

foreach (var relay in relays)
{
    var communicator = CreateCommunicator(relay);
    communicators.Add(communicator);
    multiClient.RegisterCommunicator(communicator);
}

var viewer = new NostrViewer(multiClient);

viewer.Subscribe();

communicators.ForEach(x => x.Start());

viewer.SendRequests();

exitEvent.WaitOne();

Log.Debug("====================================");
Log.Debug("              STOPPING              ");
Log.Debug("====================================");
Log.CloseAndFlush();

foreach (var communicator in communicators)
{
    await communicator.Stop(WebSocketCloseStatus.NormalClosure, string.Empty);
    await Task.Delay(500);
    communicator.Dispose();
}

static SerilogLoggerFactory InitLogging()
{
    Console.OutputEncoding = Encoding.UTF8;
    var executingDir = Path.GetDirectoryName(Assembly.GetEntryAssembly()?.Location) ?? Directory.GetCurrentDirectory();
    var logPath = Path.Combine(executingDir, "logs", "verbose.log");
    var logger = new LoggerConfiguration()
        .MinimumLevel.Verbose()
        .WriteTo.File(logPath, rollingInterval: RollingInterval.Day)
        .WriteTo.Console(LogEventLevel.Debug,
            outputTemplate: "[{Timestamp:HH:mm:ss.fff} {Level:u3}] {Message:lj}{NewLine}{Exception}",
            theme: AnsiConsoleTheme.Code)
        .CreateLogger();
    Log.Logger = logger;
    return new SerilogLoggerFactory(logger);
}

NostrWebsocketCommunicator CreateCommunicator(Uri uri)
{
    var comm = new NostrWebsocketCommunicator(uri, () =>
    {
        var client = new ClientWebSocket();
        client.Options.SetRequestHeader("Origin", "http://localhost");
        return client;
    });

    comm.Name = uri.Host;
    comm.ReconnectTimeout = null; //TimeSpan.FromSeconds(30);
    comm.ErrorReconnectTimeout = TimeSpan.FromSeconds(60);

    comm.ReconnectionHappened.Subscribe(info =>
        Log.Information("[{relay}] Reconnection happened, type: {type}", comm.Name, info.Type));
    comm.DisconnectionHappened.Subscribe(info =>
        Log.Information("[{relay}] Disconnection happened, type: {type}, reason: {reason}", comm.Name, info.Type, info.CloseStatus));
    return comm;
}

void CurrentDomainOnProcessExit(object? sender, EventArgs eventArgs)
{
    Log.Warning("Exiting process");
    exitEvent.Set();
}

void DefaultOnUnloading(AssemblyLoadContext assemblyLoadContext)
{
    Log.Warning("Unloading process");
    exitEvent.Set();
}

void ConsoleOnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
{
    Log.Warning("Canceling process");
    e.Cancel = true;
    exitEvent.Set();
}

void SendEvent(INostrClient client, int counter)
{
    var ev = new NostrEvent
    {
        Kind = NostrKind.ShortTextNote,
        CreatedAt = DateTime.UtcNow,
        Content = $"Test message {counter} from C# client"
    };

    var key = NostrPrivateKey.FromBech32("nsec1xjyhgzm2cjv2wp64wnh64d2n4s9ylguhwelekh5r38rlsfgk6mes62duaa");
    var signed = ev.Sign(key);

    client.Send(new NostrEventRequest(signed));
}

void SendDirectMessage(INostrClient client)
{
    Log.Information("Sending encrypted direct message");

    var sender = NostrPrivateKey.FromBech32("nsec1l0a7m5dlg4h9wurhnmgsq5nv9cqyvdwsutk4yf3w4fzzaqw7n80ssdfzkg");
    var receiver = NostrPublicKey.FromHex("d27790fcb3f9afa0d709b2e9c5995151bc5ad008079bd0a474aa101d80e0eed3");

    var ev = new NostrEvent
    {
        CreatedAt = DateTime.UtcNow,
        Content = $"Test private message from C# client"
    };

    var encrypted = ev.EncryptDirect(sender, receiver);
    var signed = encrypted.Sign(sender);

    client.Send(new NostrEventRequest(signed));
}

static async Task MineAndSendProofOfWorkExample(Uri[] relays)
{
    try
    {
        Console.WriteLine("Mining a Nostr event with Proof of Work...");
        
        // Generate a new private key
        var privateKey = NostrPrivateKey.GenerateNew();
        var publicKey = privateKey.DerivePublicKey();
        
        Console.WriteLine($"Using public key: {publicKey.Bech32}");
        
        // Create an event to mine
        var eventToMine = new NostrEvent
        {
            Kind = NostrKind.ShortTextNote,
            CreatedAt = DateTime.UtcNow,
            Content = "This is a test message with Proof of Work (NIP-13) from the Nostr.Client library.",
            Pubkey = publicKey.Hex
        };
        
        // Set difficulty target (10 bits = about 2.5 hex zeros)
        int targetDifficulty = 10;
        Console.WriteLine($"Mining with target difficulty: {targetDifficulty} bits...");
        
        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        
        // Mine the event
        var minedEvent = await eventToMine.GeneratePow(targetDifficulty, cancellationTokenSource.Token);
        
        // Get the achieved difficulty
        int achievedDifficulty = minedEvent.GetDifficulty();
        
        Console.WriteLine($"Mining complete! Achieved difficulty: {achievedDifficulty} bits");
        Console.WriteLine($"Event ID: {minedEvent.Id}");
        
        // Sign the mined event
        var signedEvent = minedEvent.Sign(privateKey);
        
        // Connect to relay and send the event
        using var communicator = new NostrWebsocketCommunicator(relays[0]);
        using var client = new NostrWebsocketClient(communicator, null);
        
        TaskCompletionSource<bool> sentEvent = new TaskCompletionSource<bool>();
        
        // Setup event handling
        client.Streams.EventStream.Subscribe(response => 
        {
            if (response?.Event?.Id == signedEvent.Id)
            {
                Console.WriteLine("Event was received back from relay!");
                sentEvent.TrySetResult(true);
            }
        });
        
        client.Streams.OkStream.Subscribe(response =>
        {
            if (response?.EventId == signedEvent.Id)
            {
                Console.WriteLine($"Event was accepted by relay: {response.IsSuccess}");
                if (!response.IsSuccess)
                {
                    Console.WriteLine($"Reason: {response.Message}");
                }
            }
        });
        
        // Connect to relay
        Console.WriteLine($"Connecting to relay {relays[0]}...");
        await communicator.Start();
        
        // Send the event
        Console.WriteLine("Sending mined event to relay...");
        client.Send(new Nostr.Client.Requests.NostrEventRequest(signedEvent));
        
        // Wait for confirmation (or timeout after 15 seconds)
        await Task.WhenAny(sentEvent.Task, Task.Delay(15000));
        
        Console.WriteLine("Proof of Work example completed.");
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine("Mining was canceled (took too long).");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error in PoW example: {ex.Message}");
    }
}
