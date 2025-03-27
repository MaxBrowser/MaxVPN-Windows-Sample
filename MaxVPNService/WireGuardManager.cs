using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using static MaxVPNService.WireGuardDllWrapper;

namespace MaxVPNService
{
    internal class WireGuardManager
    {
        public static IntPtr adapterHandle;
        // Method to initialize a new WireGuard adapter
        public static IntPtr InitializeWireGuardAdapter(string adapterName)
        {
            adapterHandle = WireGuardDllWrapper.WireGuardOpenAdapter(adapterName);
            if (adapterHandle != IntPtr.Zero)
            {
                WireGuardCloseAdapter(adapterHandle);  // Ensure we start fresh
            }

            Guid newAdapterGuid = Guid.NewGuid();  // Create a new GUID for the adapter
            adapterHandle = WireGuardCreateAdapter(adapterName, "WireGuard", newAdapterGuid);

            if (adapterHandle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception($"Failed to create a new WireGuard adapter. Win32 Error Code: {error}");
            }

            return adapterHandle;
        }

        // Method to configure the WireGuard adapter with a given configuration
        public static void ConfigureAdapter(IntPtr adapterHandle,WireGuardConfig config)
        {
            byte[] privateKeyBytes = Convert.FromBase64String(config.Interface.PrivateKey);
            // 1.  Interface Configuration
            WIREGUARD_INTERFACE wgInterface = new WIREGUARD_INTERFACE
            {
                Flags = WIREGUARD_INTERFACE_FLAG.WIREGUARD_INTERFACE_HAS_PRIVATE_KEY | WIREGUARD_INTERFACE_FLAG.WIREGUARD_INTERFACE_HAS_LISTEN_PORT,
                ListenPort = 51820,
                PrivateKey = new byte[WIREGUARD_KEY_LENGTH], //  Fill with your private key
                PublicKey = new byte[WIREGUARD_KEY_LENGTH],  // Will be populated by WireGuard, if needed.
                PeersCount = 1, // Number of peers
            };

            //  Fill PrivateKey.  Example (Better to use a secure method):
           
            if (privateKeyBytes.Length < WIREGUARD_KEY_LENGTH)
                Array.Clear(wgInterface.PrivateKey, 0, WIREGUARD_KEY_LENGTH);
            
            // Ensure that the byte array for the private key is large enough
            if (privateKeyBytes.Length > WIREGUARD_KEY_LENGTH)
            {
                throw new ArgumentException("The provided private key is too long to fit in the allocated byte array.");
            }

            // Copy the private key bytes to the interface's private key array
            Array.Copy(privateKeyBytes, wgInterface.PrivateKey, privateKeyBytes.Length);


            // 2. Peer Configuration
            WIREGUARD_PEER[] wgPeers = new WIREGUARD_PEER[1];  // one peer.
            wgPeers[0] = new WIREGUARD_PEER
            {
                Flags = WIREGUARD_PEER_FLAG.WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_FLAG.WIREGUARD_PEER_HAS_ENDPOINT | WIREGUARD_PEER_FLAG.WIREGUARD_PEER_REPLACE_ALLOWED_IPS,
                PublicKey = new byte[WIREGUARD_KEY_LENGTH], // Fill with peer's public key
                Endpoint = new SOCKADDR_INET
                {
                    sin_family = (ushort)AddressFamily.InterNetwork, // Or AddressFamily.InterNetworkV6
                    sin_port = (ushort)((51820 >> 8) | ((51820 & 0xFF) << 8)),
                    sin_addr = new byte[8]  //  Will hold IP Address
                },
                AllowedIPsCount = 1, // Number of Allowed IPs for this peer.
            };

            //  Fill Peer Public Key
            byte[] publicKeyBytes = Convert.FromBase64String(config.Peers[0].PublicKey);
            if (publicKeyBytes.Length < WIREGUARD_KEY_LENGTH)
                Array.Clear(wgPeers[0].PublicKey, 0, WIREGUARD_KEY_LENGTH);
            // Convert public key string to bytes

            //  Fill Peer Endpoint IP Address.

            string endpoint = config.Peers[0].Endpoint;  // e.g., "67.219.108.79:51820"
            string[] parts = endpoint.Split(':'); // Split the string to separate IP and port

            if (parts.Length == 2)
            {
                string ipString = parts[0]; // IP address part
                string portString = parts[1]; // Port number part
                IPAddress ipAddress;
                if (IPAddress.TryParse(ipString, out ipAddress))
                {
                    // Convert IP address to bytes and copy to 'sin_addr'
                    byte[] ipBytes = ipAddress.GetAddressBytes();
                    ipBytes.CopyTo(wgPeers[0].Endpoint.sin_addr, 0);

                    // Parse port number and convert to network byte order
                    ushort port = ushort.Parse(portString);
                    wgPeers[0].Endpoint.sin_family = (ushort)(ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
                    wgPeers[0].Endpoint.sin_addr = new byte[ipAddress.AddressFamily == AddressFamily.InterNetwork ? 4 : 16];
                    wgPeers[0].Endpoint.sin_port = (ushort)((port >> 8) | ((port & 0xFF) << 8)); // Network byte order
                }
            }


                // 3. Allowed IPs for Peer.
                //WIREGUARD_ALLOWED_IP[][] allowedIps = new WIREGUARD_ALLOWED_IP[1][]; // 1 Peer
                //allowedIps[0] = new WIREGUARD_ALLOWED_IP[1];  // 1 Allowed IP for Peer 0

                WIREGUARD_ALLOWED_IP[][] allAllowedIps = new WIREGUARD_ALLOWED_IP[1][];

            for (int peerIndex = 0; peerIndex < 1; peerIndex++)
            {
                string[] ipAddresses = config.Peers[peerIndex].AllowedIPs.Split(',');
                allAllowedIps[peerIndex] = new WIREGUARD_ALLOWED_IP[ipAddresses.Length];

                for (int i = 0; i < ipAddresses.Length; i++)
                {
                    string ipAddress = ipAddresses[i].Trim(); // Trim any whitespace
                    int slashIndex = ipAddress.IndexOf('/'); // Find the slash to separate IP from CIDR
                    string ip = ipAddress.Substring(0, slashIndex);
                    byte cidr = byte.Parse(ipAddress.Substring(slashIndex + 1));

                    allAllowedIps[peerIndex][i] = new WIREGUARD_ALLOWED_IP
                    {
                        AddressFamily = ip.Contains(":") ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork,
                        Address = new WIREGUARD_ALLOWED_IP.AddressUnion
                        {
                            V4 = IPAddress.Parse(ip) // Use IPAddress.Parse to handle both IPv4 and IPv6
                        },
                        Cidr = cidr
                    };
                }
            }




            // 4.  Call SetConfiguration
            if (!WireGuardDllWrapper.SetConfiguration(adapterHandle, wgInterface, wgPeers, allAllowedIps))
            {
                Console.WriteLine("Failed to set WireGuard configuration.");
                WireGuardDllWrapper.CloseAdapter(adapterHandle);
                adapterHandle = IntPtr.Zero;
                return;
            }
        }




        private static SOCKADDR_INET CreateSockaddr(string endpoint)
        {
            var ep = ConvertToIPEndPoint(endpoint);
            var sockaddr = new SOCKADDR_INET
            {
                sin_family = (ushort)(ep.AddressFamily == AddressFamily.InterNetwork ? 2 : 23),
                sin_port = (ushort)IPAddress.HostToNetworkOrder((short)ep.Port),
                sin_addr = new byte[16]
            };

            byte[] addrBytes = ep.Address.GetAddressBytes();
            Buffer.BlockCopy(addrBytes, 0, sockaddr.sin_addr, ep.AddressFamily == AddressFamily.InterNetwork ? 12 : 0, addrBytes.Length);
            return sockaddr;
        }

        private static IPEndPoint ConvertToIPEndPoint(string endpoint)
        {
            string[] ep = endpoint.Split(':');
            if (ep.Length < 2) throw new FormatException("Endpoint must be in the format IP:Port");
            return new IPEndPoint(IPAddress.Parse(ep[0]), int.Parse(ep[1]));
        }
    }
}
