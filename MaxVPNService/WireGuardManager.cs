using System;
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
                WireGuardCloseAdapter(adapterHandle); // Ensure we start fresh
            }

            Guid newAdapterGuid = Guid.NewGuid(); // Create a new GUID for the adapter
            adapterHandle = WireGuardCreateAdapter(adapterName, "WireGuard", newAdapterGuid);

            if (adapterHandle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception($"Failed to create a new WireGuard adapter. Win32 Error Code: {error}");
            }

            return adapterHandle;
        }

        // Method to configure the WireGuard adapter with a given configuration
        public static void ConfigureAdapter(IntPtr adapterHandle, WireGuardConfig config)
        {
            byte[] privateKeyBytes = Convert.FromBase64String(config.Interface.PrivateKey);

            // 1. Interface Configuration
            WIREGUARD_INTERFACE wgInterface = new WIREGUARD_INTERFACE
            {
                Flags = WIREGUARD_INTERFACE_FLAG.WIREGUARD_INTERFACE_HAS_PRIVATE_KEY,
                ListenPort = 0,
                PrivateKey = new byte[WIREGUARD_KEY_LENGTH],
                PublicKey = new byte[WIREGUARD_KEY_LENGTH],
                PeersCount = (uint)config.Peers.Count, // Use the number of peers from the config
            };

            // Fill PrivateKey.
            if (privateKeyBytes.Length > WIREGUARD_KEY_LENGTH)
            {
                throw new ArgumentException("The provided private key is too long to fit in the allocated byte array.");
            }

            Array.Clear(wgInterface.PrivateKey, 0, WIREGUARD_KEY_LENGTH);
            Array.Copy(privateKeyBytes, wgInterface.PrivateKey, privateKeyBytes.Length);

            // 2. Peer Configuration
            WIREGUARD_PEER[] wgPeers = new WIREGUARD_PEER[config.Peers.Count]; // Array of peers

            WIREGUARD_ALLOWED_IP[][] allAllowedIps = new WIREGUARD_ALLOWED_IP[config.Peers.Count][]; // important

            for (int i = 0; i < config.Peers.Count; i++)
            {
                byte[] publicKeyBytes = Convert.FromBase64String(config.Peers[i].PublicKey);
                if (publicKeyBytes.Length > WIREGUARD_KEY_LENGTH)
                {
                    throw new ArgumentException($"The provided public key for peer {i} is too long.");
                }

                wgPeers[i] = new WIREGUARD_PEER
                {
                    Flags = WIREGUARD_PEER_FLAG.WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_FLAG.WIREGUARD_PEER_HAS_ENDPOINT | WIREGUARD_PEER_FLAG.WIREGUARD_PEER_REPLACE_ALLOWED_IPS,
                    PublicKey = new byte[WIREGUARD_KEY_LENGTH],
                    Endpoint = new SOCKADDR_INET(),
                    AllowedIPsCount = (uint)config.Peers[i].AllowedIPs.Split(',').Length, // Set AllowedIPsCount dynamically
                };
                Array.Clear(wgPeers[i].PublicKey, 0, WIREGUARD_KEY_LENGTH);
                Array.Copy(publicKeyBytes, wgPeers[i].PublicKey, publicKeyBytes.Length);

                string endpoint = config.Peers[i].Endpoint;
                string[] parts = endpoint.Split(':');
                if (parts.Length == 2)
                {
                    string ipString = parts[0];
                    string portString = parts[1];
                    IPAddress ipAddress;
                    if (IPAddress.TryParse(ipString, out ipAddress))
                    {
                        wgPeers[i].Endpoint.sin_port = (ushort)ushort.Parse(portString);
                        wgPeers[i].Endpoint.SetAddress(ipAddress); // Use the helper method
                    }
                }

                // 3. Allowed IPs for Peer.
                string[] ipAddresses = config.Peers[i].AllowedIPs.Split(',');
                allAllowedIps[i] = new WIREGUARD_ALLOWED_IP[ipAddresses.Length];

                for (int j = 0; j < ipAddresses.Length; j++)
                {
                    string ipAddress = ipAddresses[j].Trim();
                    int slashIndex = ipAddress.IndexOf('/');
                    string ip = ipAddress.Substring(0, slashIndex);
                    byte cidr = byte.Parse(ipAddress.Substring(slashIndex + 1));

                    IPAddress parsedIp = IPAddress.Parse(ip);

                    // Prepare the structure to store the allowed IP
                    allAllowedIps[i][j] = new WIREGUARD_ALLOWED_IP
                    {
                        AddressFamily = (ushort)parsedIp.AddressFamily, // Cast to ushort for marshaling
                        Cidr = cidr
                    };

                    // Initialize the appropriate address field based on IP version
                    allAllowedIps[i][j].Address = new byte[16];
                    Array.Copy(parsedIp.GetAddressBytes(), allAllowedIps[i][j].Address, parsedIp.GetAddressBytes().Length);                    
                }
            }

        


            // 4. Call SetConfiguration using the byte array method
            byte[] configBytes = WireGuardDllWrapper.WireguardInterfaceToBytes(wgInterface, wgPeers, allAllowedIps);
            IntPtr configPtr = Marshal.AllocHGlobal(configBytes.Length);

            try
            {
                Marshal.Copy(configBytes, 0, configPtr, configBytes.Length);
                if (!WireGuardDllWrapper.WireGuardSetConfiguration(adapterHandle, configPtr, (UInt32)configBytes.Length))
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"Failed to set WireGuard configuration. Error Code: {error}");
                    WireGuardDllWrapper.CloseAdapter(adapterHandle);
                    adapterHandle = IntPtr.Zero;
                    throw new Exception("Failed to set WireGuard configuration.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(configPtr);
            }
        }
    }
}