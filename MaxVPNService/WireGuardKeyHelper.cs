using System;
using Sodium;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MaxVPNService
{
    public static class WireGuardKeyHelper
    {
        /// <summary>
        /// Derives the WireGuard public key from the provided private key.
        /// </summary>
        /// <param name="privateKey">A 32-byte array representing the WireGuard private key.</param>
        /// <returns>A 32-byte array representing the corresponding public key, or null if the private key is invalid.</returns>
        public static byte[] GetPublicKeyFromPrivateKey(byte[] privateKey)
        {
            if (privateKey == null || privateKey.Length != 32)
            {
                // Private key must be exactly 32 bytes
                return null;
            }

            try
            {
                return PublicKeyAuth.GeneratePublicKey(privateKey);
            }
            catch (Exception ex)
            {
                // Handle any potential exceptions during key derivation
                Console.WriteLine($"Error deriving public key: {ex.Message}");
                return null;
            }
        }
    }
}
