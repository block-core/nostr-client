using System;

namespace Nostr.Client.NostrPow.Mining
{
    /// <summary>
    /// Provides utility methods for calculating proof of work difficulty
    /// </summary>
    public static class DifficultyCalculator
    {
        /// <summary>
        /// Count the number of leading zero bits in a hash (provided as hex string)
        /// </summary>
        /// <param name="hex">Hex string representation of the hash</param>
        /// <returns>Number of leading zero bits</returns>
        public static int CountLeadingZeroBits(string hex)
        {
            if (string.IsNullOrEmpty(hex))
                return 0;
            
            int count = 0;

            for (int i = 0; i < hex.Length; i++)
            {
                if (!TryParseHexDigit(hex[i], out int nibble))
                    break;

                if (nibble == 0)
                {
                    count += 4; // Each zero hex digit represents 4 zero bits
                }
                else
                {
                    // Count leading zeros in this nibble
                    count += CountLeadingZeroBitsInNibble(nibble);
                    break;
                }
            }

            return count;
        }

        /// <summary>
        /// Count leading zero bits in a nibble (4-bit value)
        /// </summary>
        public static int CountLeadingZeroBitsInNibble(int nibble)
        {
            if (nibble >= 8) return 0;
            if (nibble >= 4) return 1;
            if (nibble >= 2) return 2;
            if (nibble >= 1) return 3;
            return 4;
        }

        /// <summary>
        /// Try to parse a hex character to its integer value
        /// </summary>
        private static bool TryParseHexDigit(char c, out int value)
        {
            if (c >= '0' && c <= '9')
            {
                value = c - '0';
                return true;
            }
            
            if (c >= 'a' && c <= 'f')
            {
                value = c - 'a' + 10;
                return true;
            }
            
            if (c >= 'A' && c <= 'F')
            {
                value = c - 'A' + 10;
                return true;
            }
            
            value = 0;
            return false;
        }
    }
}
