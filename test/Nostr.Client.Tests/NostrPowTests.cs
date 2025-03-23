using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.NostrPow.Mining;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Nostr.Client.Tests
{
    public class NostrPowTests
    {
        [Theory]
        [InlineData("000000d1b3d4ca36178939c4925a5ba9ade71593522b2011836c608742fbb905", 24)]
        [InlineData("0000000f9490e4c266e0db3024b51d5cb10c0c0498824a20c35434c5c888d783", 28)]
        [InlineData("00003576dad16c6181d07f1ea653933561b5f540144db9d95318486436a4378f", 18)]
        [InlineData("01c3d4ca36178939c4925a5ba9ade71593522b2011836c608742fbb905", 7)]
        [InlineData("f1c3d4ca36178939c4925a5ba9ade71593522b2011836c608742fbb905", 0)]
        [InlineData("", 0)]
        public void CountLeadingZeroBits_ShouldReturnCorrectCount(string hex, int expectedCount)
        {
            var result = DifficultyCalculator.CountLeadingZeroBits(hex);
            Assert.Equal(expectedCount, result);
        }

        [Theory]
        [InlineData(0, 4)]
        [InlineData(1, 3)]
        [InlineData(2, 2)]
        [InlineData(3, 2)]
        [InlineData(4, 1)]
        [InlineData(7, 1)]
        [InlineData(8, 0)]
        [InlineData(15, 0)]
        public void CountLeadingZeroBitsInNibble_ShouldReturnCorrectCount(int nibble, int expectedBits)
        {
            var result = DifficultyCalculator.CountLeadingZeroBitsInNibble(nibble);
            Assert.Equal(expectedBits, result);
        }

        [Fact]
        public async Task MineEvent_ShouldProduceValidDifficulty()
        {
            // Create a test event
            var testEvent = new NostrEvent
            {
                Kind = NostrKind.ShortTextNote,
                CreatedAt = DateTime.UtcNow,
                Content = "Testing proof of work mining",
                Pubkey = "a7319aeee29127d6bd1fb0562cf616e365a2b10d635a1cb9a86a23df4add73d7"
            };

            // Set a reasonable difficulty for the test (8 bits = 2 hex zeros)
            int targetDifficulty = 8;

            // Mine the event
            var minedEvent = await EventMiner.MineEventAsync(testEvent, targetDifficulty, CancellationToken.None);
            
            // Verify the result
            Assert.NotNull(minedEvent);
            
            // Check that a nonce tag was added
            var nonceTag = minedEvent.Tags?.FindFirstTag("nonce");
            Assert.NotNull(nonceTag);
            Assert.Equal("nonce", nonceTag.TagIdentifier);
            Assert.Equal(targetDifficulty.ToString(), nonceTag.AdditionalData[1]);
            
            // Verify that the difficulty requirement was met
            int actualDifficulty = minedEvent.GetDifficulty();
            Assert.True(actualDifficulty >= targetDifficulty, 
                $"Generated event has difficulty {actualDifficulty} which is less than required {targetDifficulty}");
            
            // Verify using the convenience method
            Assert.True(minedEvent.HasValidPow(targetDifficulty));
        }
        
        [Fact]
        public void HasValidPow_ShouldRespectTargetDifficulty()
        {
            // Create a test event with difficulty commitment less than actual difficulty
            var testEvent = new NostrEvent
            {
                Kind = NostrKind.ShortTextNote,
                CreatedAt = DateTime.UtcNow,
                Content = "Testing proof of work validation",
                Pubkey = "a7319aeee29127d6bd1fb0562cf616e365a2b10d635a1cb9a86a23df4add73d7",
                Id = "0000fd1b3d4ca36178939c4925a5ba9ade71593522b2011836c608742fbb905", // 16-bit difficulty
                Tags = new NostrEventTags(
                    new NostrEventTag("nonce", "12345", "10") // Only committed to 10-bit difficulty
                )
            };

            // Should pass validation when required difficulty is lower than committed
            Assert.True(testEvent.HasValidPow(8));
            
            // Should pass validation when required difficulty equals committed
            Assert.True(testEvent.HasValidPow(10));
            
            // Should fail validation when required difficulty is higher than committed
            // (even though actual difficulty is higher)
            Assert.False(testEvent.HasValidPow(12));
        }
        
        [Fact]
        public async Task SignedMinedEvent_ShouldBeValid()
        {
            // Create a private key
            var privateKey = NostrPrivateKey.GenerateNew();
            var publicKey = privateKey.DerivePublicKey();

            // Create a test event
            var testEvent = new NostrEvent
            {
                Kind = NostrKind.ShortTextNote,
                CreatedAt = DateTime.UtcNow,
                Content = "Testing signed proof of work",
                Pubkey = publicKey.Hex
            };
            
            // Mine the event with difficulty 8
            var minedEvent = await EventMiner.MineEventAsync(testEvent, 8, CancellationToken.None);
            
            // Sign the mined event
            var signedMinedEvent = minedEvent.Sign(privateKey);
            
            // Verify both PoW and signature
            Assert.True(signedMinedEvent.HasValidPow(8));
            Assert.True(signedMinedEvent.IsSignatureValid());
            
            // Create a tampered event with modified content
            // We need to recalculate the ID to properly test signature validation failure
            var tampered = new NostrEvent
            {
                // Don't copy the ID, it should be recalculated for the test
                Pubkey = signedMinedEvent.Pubkey,
                CreatedAt = signedMinedEvent.CreatedAt,
                Kind = signedMinedEvent.Kind,
                Tags = signedMinedEvent.Tags?.DeepClone(),
                Content = "Tampered content", // Changed content
                Sig = signedMinedEvent.Sig    // Keep the same signature
            };
            
            // A tampered event with a different content but same signature should fail validation
            Assert.False(tampered.IsSignatureValid());
        }
    }
}

