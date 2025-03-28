using System;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.ComponentModel;
using static MaxVPNService.WireGuardDllWrapper.WIREGUARD_ALLOWED_IP;

namespace MaxVPNService
{
    public static class WireGuardDllWrapper
    {
        // Constants
        public const int WIREGUARD_KEY_LENGTH = 32;

        // Enums
        public enum WIREGUARD_LOGGER_LEVEL
        {
            WIREGUARD_LOG_INFO,
            WIREGUARD_LOG_WARN,
            WIREGUARD_LOG_ERR
        }

        public enum WIREGUARD_ADAPTER_LOG_STATE
        {
            WIREGUARD_ADAPTER_LOG_OFF,
            WIREGUARD_ADAPTER_LOG_ON,
            WIREGUARD_ADAPTER_LOG_ON_WITH_PREFIX
        }

        public enum WIREGUARD_ADAPTER_STATE
        {
            WIREGUARD_ADAPTER_STATE_DOWN,
            WIREGUARD_ADAPTER_STATE_UP
        }

        [Flags]
        public enum WIREGUARD_PEER_FLAG : uint
        {
            WIREGUARD_PEER_HAS_PUBLIC_KEY = 1 << 0,
            WIREGUARD_PEER_HAS_PRESHARED_KEY = 1 << 1,
            WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2,
            WIREGUARD_PEER_HAS_ENDPOINT = 1 << 3,
            WIREGUARD_PEER_REPLACE_ALLOWED_IPS = 1 << 5,
            WIREGUARD_PEER_REMOVE = 1 << 6,
            WIREGUARD_PEER_UPDATE = 1 << 7
        }

        [Flags]
        public enum WIREGUARD_INTERFACE_FLAG : uint
        {
            WIREGUARD_INTERFACE_HAS_PUBLIC_KEY = (1 << 0),
            WIREGUARD_INTERFACE_HAS_PRIVATE_KEY = (1 << 1),
            WIREGUARD_INTERFACE_HAS_LISTEN_PORT = (1 << 2),
            WIREGUARD_INTERFACE_REPLACE_PEERS = (1 << 3)
        }

        // Structs
        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct WIREGUARD_ALLOWED_IP
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Address;
            public ushort AddressFamily;  // ADDRESS_FAMILY is usually a 16-bit value
            public byte Cidr;
            // 5 bytes of padding to reach 24 total
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
            private byte[] __padding;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct WIREGUARD_PEER
        {
            public WIREGUARD_PEER_FLAG Flags;
            public uint Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WIREGUARD_KEY_LENGTH)]
            public byte[] PublicKey;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WIREGUARD_KEY_LENGTH)]
            public byte[] PresharedKey;
            public ushort PersistentKeepalive;
            public SOCKADDR_INET Endpoint;
            public ulong TxBytes;
            public ulong RxBytes;
            public ulong LastHandshake;
            public uint AllowedIPsCount;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct WIREGUARD_INTERFACE
        {
            public WIREGUARD_INTERFACE_FLAG Flags;
            public ushort ListenPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WIREGUARD_KEY_LENGTH)]
            public byte[] PrivateKey;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WIREGUARD_KEY_LENGTH)]
            public byte[] PublicKey;
            public uint PeersCount;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SOCKADDR_INET
        {
            public ushort sin_family;
            public ushort sin_port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] // Increased size to accommodate IPv6
            public byte[] sin_addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sin_zero;

            // Helper method to set the address based on IPAddress
            public void SetAddress(IPAddress ipAddress)
            {
                sin_family = (ushort)(ipAddress.AddressFamily == AddressFamily.InterNetworkV6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
                sin_port = (ushort)IPAddress.HostToNetworkOrder((short)ushort.Parse(sin_port.ToString())); // Ensure port is in network order

                byte[] ipBytes = ipAddress.GetAddressBytes();
                if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
                {
                    sin_addr = new byte[16]; // Initialize to 16
                    ipBytes.CopyTo(sin_addr, 0);
                    // Pad the remaining bytes if needed (though likely not strictly necessary)
                }
                else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    sin_addr = new byte[16];
                    ipBytes.CopyTo(sin_addr, 0);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NET_LUID
        {
            public ulong Value;
        }

        // Delegates
        public delegate void WIREGUARD_LOGGER_CALLBACK(WIREGUARD_LOGGER_LEVEL Level, ulong Timestamp, [MarshalAs(UnmanagedType.LPWStr)] string Message);

        // Import DLL functions
        [DllImport("wireguard.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WireGuardCreateAdapter(string Name, string TunnelType, [MarshalAs(UnmanagedType.LPStruct)] Guid RequestedGUID);

        [DllImport("wireguard.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WireGuardOpenAdapter(string Name);

        [DllImport("wireguard.dll", SetLastError = true)]
        public static extern void WireGuardCloseAdapter(IntPtr Adapter);

        [DllImport("wireguard.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WireGuardDeleteDriver();

        [DllImport("wireguard.dll")]
        public static extern void WireGuardGetAdapterLUID(IntPtr Adapter, out NET_LUID Luid);

        [DllImport("wireguard.dll", SetLastError = true)]
        public static extern uint WireGuardGetRunningDriverVersion();

        [DllImport("wireguard.dll")]
        public static extern void WireGuardSetLogger(WIREGUARD_LOGGER_CALLBACK NewLogger);

        [DllImport("wireguard.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WireGuardSetAdapterLogging(IntPtr Adapter, WIREGUARD_ADAPTER_LOG_STATE LogState);

        [DllImport("wireguard.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WireGuardSetAdapterState(IntPtr Adapter, WIREGUARD_ADAPTER_STATE State);

        [DllImport("wireguard.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WireGuardGetAdapterState(IntPtr Adapter, out WIREGUARD_ADAPTER_STATE State);

        [DllImport("wireguard.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WireGuardSetConfiguration(IntPtr Adapter, IntPtr Config, uint Bytes);

        [DllImport("wireguard.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WireGuardGetConfiguration(IntPtr Adapter, IntPtr Config, ref uint Bytes);

        public static IntPtr CreateAdapter(string name, string tunnelType, Guid requestedGuid)
        {
            IntPtr adapter = WireGuardCreateAdapter(name, tunnelType, requestedGuid);
            if (adapter == IntPtr.Zero)
            {
                throw new Win32Exception();
            }
            return adapter;
        }

        public static IntPtr OpenAdapter(string name)
        {
            IntPtr adapter = WireGuardOpenAdapter(name);
            if (adapter == IntPtr.Zero)
            {
                throw new Win32Exception();
            }
            return adapter;
        }

        public static void CloseAdapter(IntPtr adapter)
        {
            WireGuardCloseAdapter(adapter);
        }

        public static bool DeleteDriver()
        {
            bool result = WireGuardDeleteDriver();
            if (!result)
            {
                throw new Win32Exception();
            }
            return result;
        }

        public static NET_LUID GetAdapterLuid(IntPtr adapter)
        {
            NET_LUID luid;
            WireGuardGetAdapterLUID(adapter, out luid);
            return luid;
        }

        public static uint GetRunningDriverVersion()
        {
            uint version = WireGuardGetRunningDriverVersion();
            if (version == 0)
            {
                throw new Win32Exception(); //  Consider checking for ERROR_FILE_NOT_FOUND
            }
            return version;
        }

        public static void SetLogger(WIREGUARD_LOGGER_CALLBACK newLogger)
        {
            WireGuardSetLogger(newLogger);
        }

        public static bool SetAdapterLogging(IntPtr adapter, WIREGUARD_ADAPTER_LOG_STATE logState)
        {
            bool result = WireGuardSetAdapterLogging(adapter, logState);
            if (!result)
            {
                throw new Win32Exception();
            }
            return result;
        }

        public static bool SetAdapterState(IntPtr adapter, WIREGUARD_ADAPTER_STATE state)
        {
            bool result = WireGuardSetAdapterState(adapter, state);
            if (!result)
            {
                throw new Win32Exception();
            }
            return result;
        }

        public static WIREGUARD_ADAPTER_STATE GetAdapterState(IntPtr adapter)
        {
            WIREGUARD_ADAPTER_STATE state;
            if (!WireGuardGetAdapterState(adapter, out state))
            {
                throw new Win32Exception();
            }
            return state;
        }

        public static byte[] WireguardInterfaceToBytes(
            WIREGUARD_INTERFACE config,
            WIREGUARD_PEER[] peers,
            WIREGUARD_ALLOWED_IP[][] allowedIps)
        {
            // 1) Calculate total buffer size
            int sizeOfInterface = Marshal.SizeOf(typeof(WIREGUARD_INTERFACE));
            int sizeOfPeer = Marshal.SizeOf(typeof(WIREGUARD_PEER));

            // Each _WIREGUARD_ALLOWED_IP is 24 bytes (8-byte aligned)
            const int SIZE_OF_ALLOWED_IP = 24;

            // Start buffer size with the interface struct
            int bufferSize = sizeOfInterface;

            // Add each peer
            if (peers != null)
            {
                foreach (WIREGUARD_PEER peer in peers)
                {
                    bufferSize += sizeOfPeer;

                    // Add each allowed IP
                    int index = Array.IndexOf(peers, peer);
                    if (allowedIps != null && index >= 0 && index < allowedIps.Length)
                    {
                        WIREGUARD_ALLOWED_IP[] ipArray = allowedIps[index];
                        if (ipArray != null)
                        {
                            // Each WIREGUARD_ALLOWED_IP = 24 bytes
                            bufferSize += ipArray.Length * SIZE_OF_ALLOWED_IP;
                        }
                    }
                }
            }

            // 2) Allocate the buffer
            byte[] buffer = new byte[bufferSize];
            IntPtr bufferPtr = Marshal.AllocHGlobal(bufferSize);
            IntPtr currentPtr = bufferPtr;

            try
            {
                // 3) Write the WIREGUARD_INTERFACE struct
                Marshal.StructureToPtr(config, currentPtr, false);
                currentPtr += sizeOfInterface;

                // 4) For each peer, write the peer struct and its AllowedIPs
                if (peers != null)
                {
                    for (int p = 0; p < peers.Length; p++)
                    {
                        Marshal.StructureToPtr(peers[p], currentPtr, false);
                        currentPtr += sizeOfPeer;

                        // 5) Manually write each WIREGUARD_ALLOWED_IP (24 bytes each)
                        if (allowedIps != null && p < allowedIps.Length && allowedIps[p] != null)
                        {
                            foreach (WIREGUARD_ALLOWED_IP ip in allowedIps[p])
                            {
                                // -- (a) Write 16 bytes for the union
                                // Even if IPv4 is only 4 bytes, the union is 16 bytes in C.
                                bool isV4 = (ip.AddressFamily == (ushort)AddressFamily.InterNetwork);
                                // If it’s IPv4, copy the first 4 bytes into a 16-byte array (the rest can be zero).
                                byte[] unionBytes = new byte[16];
                                if (isV4 && ip.Address != null)
                                {
                                    Array.Copy(ip.Address, 0, unionBytes, 0, 4);
                                }
                                else if (!isV4 && ip.Address != null)
                                {
                                    Array.Copy(ip.Address, 0, unionBytes, 0, 16);
                                }

                                // Copy that into unmanaged memory
                                Marshal.Copy(unionBytes, 0, currentPtr, 16);
                                currentPtr += 16;

                                // -- (b) Write 2 bytes for AddressFamily
                                short af = (short)ip.AddressFamily;
                                Marshal.WriteInt16(currentPtr, af);
                                currentPtr += 2;

                                // -- (c) Write 1 byte for Cidr
                                Marshal.WriteByte(currentPtr, ip.Cidr);
                                currentPtr += 1;

                                // -- (d) Add 5 bytes of padding to reach 24 bytes total
                                currentPtr += 5;
                            }
                        }
                    }
                }

                // 6) Copy the unmanaged buffer back to a managed byte array
                Marshal.Copy(bufferPtr, buffer, 0, bufferSize);
            }
            finally
            {
                Marshal.FreeHGlobal(bufferPtr);
            }

            return buffer;
        }

      

        public static (WIREGUARD_INTERFACE config, WIREGUARD_PEER[] peers, WIREGUARD_ALLOWED_IP[][] allowedIps) GetConfiguration(IntPtr adapter)
        {
            uint size = 0;
            if (!WireGuardGetConfiguration(adapter, IntPtr.Zero, ref size))
            {
                if (Marshal.GetLastWin32Error() != 122) //122 = ERROR_INSUFFICIENT_BUFFER
                    throw new Win32Exception();
            }

            if (size == 0)
            {
                return (new WIREGUARD_INTERFACE(), Array.Empty<WIREGUARD_PEER>(), Array.Empty<WIREGUARD_ALLOWED_IP[]>());
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!WireGuardGetConfiguration(adapter, buffer, ref size))
                {
                    throw new Win32Exception();
                }

                WIREGUARD_INTERFACE config = (WIREGUARD_INTERFACE)Marshal.PtrToStructure(buffer, typeof(WIREGUARD_INTERFACE));
                uint peersCount = config.PeersCount;

                WIREGUARD_PEER[] peers = new WIREGUARD_PEER[peersCount];
                WIREGUARD_ALLOWED_IP[][] allowedIps = new WIREGUARD_ALLOWED_IP[peersCount][];

                IntPtr currentPtr = buffer + Marshal.SizeOf(typeof(WIREGUARD_INTERFACE));

                for (int i = 0; i < peersCount; i++)
                {
                    peers[i] = (WIREGUARD_PEER)Marshal.PtrToStructure(currentPtr, typeof(WIREGUARD_PEER));
                    currentPtr += Marshal.SizeOf(typeof(WIREGUARD_PEER));
                    uint allowedIpsCount = peers[i].AllowedIPsCount;
                    allowedIps[i] = new WIREGUARD_ALLOWED_IP[allowedIpsCount];

                    for (int j = 0; j < allowedIpsCount; j++)
                    {
                        allowedIps[i][j] = (WIREGUARD_ALLOWED_IP)Marshal.PtrToStructure(currentPtr, typeof(WIREGUARD_ALLOWED_IP));
                        currentPtr += Marshal.SizeOf(typeof(WIREGUARD_ALLOWED_IP));
                    }
                }

                return (config, peers, allowedIps);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

    }
}