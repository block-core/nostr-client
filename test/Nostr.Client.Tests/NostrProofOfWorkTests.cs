using Nostr.Client.Keys;
using Nostr.Client.Messages;
using Nostr.Client.Utils;

namespace Nostr.Client.Tests
{
    public class NostrProofOfWorkTests
    {
        [Fact]
        public void CountLeadingZeroBits_WithAllZeros_ShouldReturn256()
        {
            var hex = new string('0', 64); // 32 bytes = 256 bits
            var result = NostrProofOfWork.CountLeadingZeroBits(hex);
            Assert.Equal(256, result);
        }

        [Fact]
        public void CountLeadingZeroBits_WithNoLeadingZeros_ShouldReturn0()
        {
            var hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            var result = NostrProofOfWork.CountLeadingZeroBits(hex);
            Assert.Equal(0, result);
        }

        [Fact]
        public void CountLeadingZeroBits_WithOneLeadingZeroByte_ShouldReturn8()
        {
            var hex = "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            var result = NostrProofOfWork.CountLeadingZeroBits(hex);
            Assert.Equal(8, result);
        }

        [Fact]
        public void CountLeadingZeroBits_WithPartialLeadingZeroBits_ShouldReturnCorrectCount()
        {
            // 0x0F = 00001111 in binary, so 4 leading zero bits
            var hex = "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            var result = NostrProofOfWork.CountLeadingZeroBits(hex);
            Assert.Equal(4, result);
        }

        [Fact]
        public void CountLeadingZeroBits_WithMultipleLeadingZeroBytes_ShouldReturnCorrectCount()
        {
            // 3 zero bytes = 24 bits, plus 0x01 = 00000001 = 7 more bits = 31 total
            string hex = "00000001ffffffffffffffffffffffffffffffffffffffffffffffffffff";
            var result = NostrProofOfWork.CountLeadingZeroBits(hex);
            Assert.Equal(31, result);
        }

        [Fact]
        public void CountLeadingZeroBits_WithNullOrEmpty_ShouldReturn0()
        {
            Assert.Equal(0, NostrProofOfWork.CountLeadingZeroBits((string?)null));
            Assert.Equal(0, NostrProofOfWork.CountLeadingZeroBits(""));
            Assert.Equal(0, NostrProofOfWork.CountLeadingZeroBits("   "));
        }

        [Fact]
        public void ValidateProofOfWork_WithoutNonceTag_AndZeroMinimum_ShouldReturnTrue()
        {
            var ev = new NostrEvent
            {
                Id = "0000000000000000000000000000000000000000000000000000000000000000",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = NostrEventTags.Empty
            };

            var result = NostrProofOfWork.ValidateProofOfWork(ev, 0);
            Assert.True(result);
        }

        [Fact]
        public void ValidateProofOfWork_WithoutNonceTag_AndNonZeroMinimum_ShouldReturnFalse()
        {
            var ev = new NostrEvent
            {
                Id = "0000000000000000000000000000000000000000000000000000000000000000",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = NostrEventTags.Empty
            };

            var result = NostrProofOfWork.ValidateProofOfWork(ev, 10);
            Assert.False(result);
        }

        [Fact]
        public void ValidateProofOfWork_WithValidNonceTag_ShouldReturnTrue()
        {
            // Event ID with 16 leading zero bits (2 zero bytes)
            var ev = new NostrEvent
            {
                Id = "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = new NostrEventTags(new NostrEventTag("nonce", "12345", "16"))
            };

            var result = NostrProofOfWork.ValidateProofOfWork(ev, 16);
            Assert.True(result);
        }

        [Fact]
        public void ValidateProofOfWork_WithInsufficientDifficulty_ShouldReturnFalse()
        {
            // Event ID with 8 leading zero bits (1 zero byte)
            var ev = new NostrEvent
            {
                Id = "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = new NostrEventTags(new NostrEventTag("nonce", "12345", "8"))
            };

            var result = NostrProofOfWork.ValidateProofOfWork(ev, 16);
            Assert.False(result);
        }

        [Fact]
        public void ValidateProofOfWork_WithTargetLowerThanMinimum_ShouldReturnFalse()
        {
            // Event ID with 16 leading zero bits but target is only 8
            var ev = new NostrEvent
            {
                Id = "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = new NostrEventTags(new NostrEventTag("nonce", "12345", "8"))
            };

            var result = NostrProofOfWork.ValidateProofOfWork(ev, 16);
            Assert.False(result);
        }

        [Fact]
        public void GetDifficulty_WithValidId_ShouldReturnCorrectDifficulty()
        {
            var ev = new NostrEvent
            {
                Id = "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test"
            };

            var difficulty = NostrProofOfWork.GetDifficulty(ev);
            Assert.Equal(16, difficulty);
        }

        [Fact]
        public void GetTargetDifficulty_WithValidNonceTag_ShouldReturnTargetDifficulty()
        {
            var ev = new NostrEvent
            {
                Id = "test",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = new NostrEventTags(new NostrEventTag("nonce", "12345", "20"))
            };

            var targetDifficulty = NostrProofOfWork.GetTargetDifficulty(ev);
            Assert.Equal(20, targetDifficulty);
        }

        [Fact]
        public void GetTargetDifficulty_WithoutNonceTag_ShouldReturn0()
        {
            var ev = new NostrEvent
            {
                Id = "test",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = NostrEventTags.Empty
            };

            var targetDifficulty = NostrProofOfWork.GetTargetDifficulty(ev);
            Assert.Equal(0, targetDifficulty);
        }

        [Fact]
        public void MineProofOfWork_WithZeroDifficulty_ShouldReturnClone()
        {
            var ev = new NostrEvent
            {
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test"
            };

            var mined = NostrProofOfWork.MineProofOfWork(ev, 0);

            Assert.NotNull(mined);
            Assert.Equal(ev.Content, mined.Content);
            Assert.Equal(ev.Pubkey, mined.Pubkey);
        }

        [Fact]
        public void MineProofOfWork_WithLowDifficulty_ShouldFindValidProof()
        {
            var privateKey = NostrPrivateKey.GenerateNew();
            var publicKey = privateKey.DerivePublicKey();
            
            var ev = new NostrEvent
            {
                Pubkey = publicKey.Hex,
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test mining",
                Tags = NostrEventTags.Empty
            };

            // Use low difficulty for fast test
            var targetDifficulty = 8;
            var mined = NostrProofOfWork.MineProofOfWork(ev, targetDifficulty, maxIterations: 100000);

            Assert.NotNull(mined);
            Assert.True(mined.ValidateProofOfWork(targetDifficulty));
            Assert.True(mined.GetDifficulty() >= targetDifficulty);
            Assert.Equal(targetDifficulty, mined.GetTargetDifficulty());
            
            // Verify nonce tag exists
            var nonceTag = mined.Tags?.FindFirstTag("nonce");
            Assert.NotNull(nonceTag);
            Assert.Equal(2, nonceTag.AdditionalData.Length); // nonce value + target difficulty
        }

        [Fact]
        public void MineProofOfWork_WithMaxIterations_ShouldReturnNullIfNotFound()
        {
            var ev = new NostrEvent
            {
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test"
            };

            // Use very high difficulty and low max iterations to ensure it won't be found
            var mined = NostrProofOfWork.MineProofOfWork(ev, 100, maxIterations: 10);

            Assert.Null(mined);
        }

        [Fact]
        public void MineProofOfWork_WithCancellation_ShouldReturnNull()
        {
            var ev = new NostrEvent
            {
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test"
            };

            var cts = new CancellationTokenSource();
            cts.Cancel(); // Cancel immediately

            var mined = NostrProofOfWork.MineProofOfWork(ev, 20, cts.Token);

            Assert.Null(mined);
        }

        [Fact]
        public void MineProofOfWork_WithProgressCallback_ShouldReportProgress()
        {
            var ev = new NostrEvent
            {
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test mining with progress"
            };

            var progressReports = new List<(long nonce, int difficulty)>();
            
            var mined = NostrProofOfWork.MineProofOfWork(
                ev, 
                8, 
                (nonce, difficulty) => progressReports.Add((nonce, difficulty)),
                progressReportInterval: 1000,
                maxIterations: 100000);

            Assert.NotNull(mined);
            Assert.True(progressReports.Count > 0, "Progress callback should have been called");
        }

        [Fact]
        public void NostrEvent_ValidateProofOfWork_ExtensionMethod_ShouldWork()
        {
            var ev = new NostrEvent
            {
                Id = "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = new NostrEventTags(new NostrEventTag("nonce", "12345", "16"))
            };

            Assert.True(ev.ValidateProofOfWork(16));
            Assert.Equal(16, ev.GetDifficulty());
            Assert.Equal(16, ev.GetTargetDifficulty());
        }

        [Fact]
        public void NostrEvent_MineProofOfWork_ExtensionMethod_ShouldWork()
        {
            var ev = new NostrEvent
            {
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test extension"
            };

            var mined = ev.MineProofOfWork(8, maxIterations: 100000);

            Assert.NotNull(mined);
            Assert.True(mined.ValidateProofOfWork(8));
        }

        [Fact]
        public void MineProofOfWork_ShouldPreserveEventProperties()
        {
            var createdAt = DateTime.UtcNow;
            var ev = new NostrEvent
            {
                Pubkey = "testpubkey123",
                CreatedAt = createdAt,
                Kind = NostrKind.ShortTextNote,
                Content = "test content preservation",
                Tags = new NostrEventTags(
                    new NostrEventTag("e", "someeventid"),
                    new NostrEventTag("p", "somepubkey")
                )
            };

            var mined = NostrProofOfWork.MineProofOfWork(ev, 8, maxIterations: 100000);

            Assert.NotNull(mined);
            Assert.Equal(ev.Pubkey, mined.Pubkey);
            Assert.Equal(ev.CreatedAt, mined.CreatedAt);
            Assert.Equal(ev.Kind, mined.Kind);
            Assert.Equal(ev.Content, mined.Content);
            
            // Should have original tags plus nonce tag
            Assert.True(mined.Tags?.ContainsTag("e") ?? false);
            Assert.True(mined.Tags?.ContainsTag("p") ?? false);
            Assert.True(mined.Tags?.ContainsTag("nonce") ?? false);
        }

        [Fact]
        public void MineProofOfWork_WithExistingNonceTag_ShouldReplaceIt()
        {
            var ev = new NostrEvent
            {
                Pubkey = "test",
                CreatedAt = DateTime.UtcNow,
                Kind = NostrKind.ShortTextNote,
                Content = "test",
                Tags = new NostrEventTags(
                    new NostrEventTag("nonce", "999", "5"),
                    new NostrEventTag("e", "someid")
                )
            };

            var mined = NostrProofOfWork.MineProofOfWork(ev, 8, maxIterations: 100000);

            Assert.NotNull(mined);
            
            // Should have only one nonce tag
            var nonceTags = mined.Tags?.Get("nonce");
            Assert.NotNull(nonceTags);
            Assert.Single(nonceTags);
            
            // Nonce value should be different from original
            var nonceTag = nonceTags.First();
            Assert.NotEqual("999", nonceTag.AdditionalData[0]);
            Assert.Equal("8", nonceTag.AdditionalData[1]);
        }
    }
}

