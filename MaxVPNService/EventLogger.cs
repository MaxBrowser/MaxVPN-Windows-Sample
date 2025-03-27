using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using static MaxVPNService.WireGuardDllWrapper;


namespace MaxVPNService
{
    public static class EventLoggerHelper
    {
        private static string eventSourceName = "MaxVPNService"; // Replace with your service name

        // Ensure the source is created if it doesn't exist
        public static void EnsureEventSourceCreated()
        {
            if (!EventLog.SourceExists(eventSourceName))
            {
                EventLog.CreateEventSource(eventSourceName, "Application");
            }
        }

        public static void LogInterfaceContents(WIREGUARD_INTERFACE wgInterface)
        {
            EnsureEventSourceCreated();
            string logMessage = $"WireGuard Interface Contents:\n" +
                                $"  Flags: {wgInterface.Flags}\n" +
                                $"  ListenPort: {wgInterface.ListenPort}\n" +
                                $"  PrivateKey (first 8 bytes): {BitConverter.ToString(wgInterface.PrivateKey.Take(8).ToArray())}\n" +
                                $"  PublicKey (first 8 bytes): {BitConverter.ToString(wgInterface.PublicKey.Take(8).ToArray())}\n" +
                                $"  PeersCount: {wgInterface.PeersCount}";
            EventLog.WriteEntry(eventSourceName, logMessage, EventLogEntryType.Information);
        }

        public static void LogPeerContents(WIREGUARD_PEER wgPeer, int index)
        {
            EnsureEventSourceCreated();
            string logMessage = $"WireGuard Peer Contents (Index {index}):\n" +
                                $"  Flags: {wgPeer.Flags}\n" +
                                $"  PublicKey (first 8 bytes): {BitConverter.ToString(wgPeer.PublicKey.Take(8).ToArray())}\n" +
                                $"  PresharedKey (first 8 bytes): {BitConverter.ToString(wgPeer.PresharedKey.Take(8).ToArray())}\n" +
                                $"  PersistentKeepalive: {wgPeer.PersistentKeepalive}\n" +
                                $"  Endpoint Family: {wgPeer.Endpoint.sin_family}\n" +
                                $"  Endpoint Port: {wgPeer.Endpoint.sin_port}\n" +
                                $"  Endpoint Address (first few bytes): {BitConverter.ToString(wgPeer.Endpoint.sin_addr.Take(8).ToArray())}\n" +
                                $"  AllowedIPsCount: {wgPeer.AllowedIPsCount}";
            EventLog.WriteEntry(eventSourceName, logMessage, EventLogEntryType.Information);
        }

        public static void LogAllowedIpContents(WIREGUARD_ALLOWED_IP allowedIp, int peerIndex, int ipIndex)
        {
            EnsureEventSourceCreated();
            string address = "";
            if (allowedIp.AddressFamily == AddressFamily.InterNetwork)
            {
                address = $"{allowedIp.Address.V4[0]}.{allowedIp.Address.V4[1]}.{allowedIp.Address.V4[2]}.{allowedIp.Address.V4[3]}";
            }
            else if (allowedIp.AddressFamily == AddressFamily.InterNetworkV6)
            {
                address = $"{BitConverter.ToString(allowedIp.Address.V6)}";
            }

            string logMessage = $"WireGuard Allowed IP Contents (Peer {peerIndex}, IP {ipIndex}):\n" +
                                $"  AddressFamily: {allowedIp.AddressFamily}\n" +
                                $"  Cidr: {allowedIp.Cidr}\n" +
                                $"  Address: {address}";
            EventLog.WriteEntry(eventSourceName, logMessage, EventLogEntryType.Information);
        }
    }
}
