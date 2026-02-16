using System;
using System.Security.Cryptography;

namespace NostrDebug.Web.Pow
{
    /// <summary>
    /// Delegate definition for PoW calculation progress reporting
    /// </summary>
    /// <param name="currentNonce">The current nonce being tested</param>
    /// <param name="difficulty">The difficulty of the current nonce</param>
    /// <param name="attemptsCount">The number of attempts made so far</param>
    public delegate void PowProgressCallback(string currentNonce, int difficulty, long attemptsCount);
    
    /// <summary>
    /// Delegate definition for PoW calculation completion
    /// </summary>
    /// <param name="success">Whether the PoW calculation was successful</param>
    /// <param name="nonce">The final nonce (if successful)</param>
    /// <param name="difficulty">The difficulty achieved</param>
    /// <param name="totalAttempts">The total number of attempts made</param>
    /// <param name="elapsedMs">The time taken in milliseconds</param>
    public delegate void PowCompletionCallback(bool success, string nonce, int difficulty, long totalAttempts, long elapsedMs);
    
    public class PowCalculator
    {
        // Declare delegate instances as events
        public event PowProgressCallback OnProgress;
        public event PowCompletionCallback OnCompletion;
        
        private CancellationTokenSource _cancellationTokenSource;
        private bool _isRunning;
        
        /// <summary>
        /// Starts calculating a Proof of Work nonce for the given event ID
        /// </summary>
        /// <param name="eventId">The event ID to calculate PoW for</param>
        /// <param name="targetDifficulty">The target difficulty to achieve</param>
        /// <param name="nonceSize">The size of the nonce in bytes</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task StartCalculation(string eventId, int targetDifficulty, int nonceSize = 4)
        {
            if (_isRunning)
            {
                throw new InvalidOperationException("A PoW calculation is already running");
            }
            
            if (string.IsNullOrEmpty(eventId))
            {
                throw new ArgumentException("Event ID cannot be null or empty", nameof(eventId));
            }
            
            _isRunning = true;
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;
            
            await Task.Run(async () =>
            {
                var random = new Random();
                var nonceBytes = new byte[nonceSize];
                var attempts = 0L;
                var startTime = DateTime.UtcNow;
                var lastProgressUpdate = DateTime.UtcNow;
                
                try
                {
                    while (!token.IsCancellationRequested)
                    {
                        // Generate random nonce
                        random.NextBytes(nonceBytes);
                        string nonceHex = BitConverter.ToString(nonceBytes).Replace("-", "").ToLower();
                        
                        // Calculate difficulty with this nonce
                        int difficulty = CalculateLeadingZeroBits(nonceHex + eventId);
                        
                        attempts++;
                        
                        // Report progress every 100 attempts or 500ms
                        if (attempts % 100 == 0 || (DateTime.UtcNow - lastProgressUpdate).TotalMilliseconds > 500)
                        {
                            OnProgress?.Invoke(nonceHex, difficulty, attempts);
                            lastProgressUpdate = DateTime.UtcNow;
                        }
                        
                        // If we found a nonce that meets or exceeds the target difficulty
                        if (difficulty >= targetDifficulty)
                        {
                            var elapsedMs = (long)(DateTime.UtcNow - startTime).TotalMilliseconds;
                            OnCompletion?.Invoke(true, nonceHex, difficulty, attempts, elapsedMs);
                            return;
                        }
                    }
                    
                    // Calculation was cancelled
                    var elapsedCancelMs = (long)(DateTime.UtcNow - startTime).TotalMilliseconds;
                    OnCompletion?.Invoke(false, string.Empty, 0, attempts, elapsedCancelMs);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in PoW calculation: {ex.Message}");
                    OnCompletion?.Invoke(false, string.Empty, 0, attempts, 0);
                }
                finally
                {
                    _isRunning = false;
                }
            }, token);
        }
        
        /// <summary>
        /// Cancels the current PoW calculation
        /// </summary>
        public void CancelCalculation()
        {
            _cancellationTokenSource?.Cancel();
        }
        
        /// <summary>
        /// Calculates the number of leading zero bits in the SHA-256 hash of the input
        /// </summary>
        /// <param name="hex">The hex string to calculate the leading zero bits for</param>
        /// <returns>The number of leading zero bits</returns>
        private int CalculateLeadingZeroBits(string hex)
        {
            try
            {
                // Convert hex string to byte array
                byte[] bytes = StringToByteArray(hex);
                
                // Calculate SHA-256
                using SHA256 sha256 = SHA256.Create();
                byte[] hash = sha256.ComputeHash(bytes);
                
                // Count leading zero bits
                int leadingZeros = 0;
                foreach (byte b in hash)
                {
                    if (b == 0)
                    {
                        leadingZeros += 8;
                    }
                    else
                    {
                        int zeros = 0;
                        for (int i = 7; i >= 0; i--)
                        {
                            if ((b & (1 << i)) == 0)
                            {
                                zeros++;
                            }
                            else
                            {
                                break;
                            }
                        }
                        leadingZeros += zeros;
                        break;
                    }
                }
                
                return leadingZeros;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error calculating difficulty: {ex.Message}");
                return 0;
            }
        }
        
        private byte[] StringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            
            return bytes;
        }
    }
}
