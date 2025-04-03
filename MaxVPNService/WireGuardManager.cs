using System;
using Vanara.PInvoke;
using System.Diagnostics;
using System.IO;
using static Vanara.PInvoke.IpHlpApi;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MaxVPNService
{
    public class istatus
    {
       public ulong rx, tx;
       public WireGuardAdapterState state;
       public istatus()
       {
            rx = 0;
            tx = 0;
            state = WireGuardAdapterState.WIREGUARD_ADAPTER_STATE_DOWN;
       }
    }
    public sealed class WireGuardManager : IDisposable
    {
        private static WireGuardManager _instance = null;
        private static readonly object _lock = new object();
        private static Adapter _wireGuardAdapter;
        private EventLog _eventLog;
        private static Guid adapterGuid = Guid.NewGuid();
        private static IpHlpApi.NET_LUID _adapterLuid;
        private static string adaptername = "max0";
        private static WgConfig WgConfig = new WgConfig();

        private WireGuardManager()
        {
            // Private constructor to prevent external instantiation
        }

        public void SetEventLog(EventLog eventLog)
        {
            _eventLog = eventLog;
        }
        private void LogInformation(string message)
        {
            _eventLog?.WriteEntry(message, EventLogEntryType.Information);
        }

        private void LogWarning(string message)
        {
            _eventLog?.WriteEntry(message, EventLogEntryType.Warning);
        }

        private void LogError(string message)
        {
            _eventLog?.WriteEntry(message, EventLogEntryType.Error);
        }

        public static WireGuardManager Instance
        {
            get
            {
                lock (_lock)
                {
                    if (_instance == null)
                    {
                        _instance = new WireGuardManager();
                    }
                    return _instance;
                }
            }
        }

        public bool InitializeAdapter()
        {
            try
            {                
                if (_wireGuardAdapter != null)
                {
                    Disconnect();
                }

                _wireGuardAdapter = new Adapter("max0", "WireGuard");                
                _wireGuardAdapter.Init(ref adapterGuid, out _adapterLuid);
                LogInformation($"WireGuard Adapter 'max0' initialized with GUID: {adapterGuid} and LUID: {_adapterLuid}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"[WireGuardManager] Error initializing adapter: {ex.Message}");
                return false;
            }
        }

        public bool LoadConfiguration(string configFileContent)
        {
            try
            {
                if (_wireGuardAdapter == null)
                {
                    if (!InitializeAdapter())
                    {
                        return false;
                    }
                }

               

                string[] lines = configFileContent.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                bool success = _wireGuardAdapter.ParseConfFile(lines, out WgConfig);

                if (success)
                {
                     Win32Error lastError;
                    lastError = GetIpForwardTable2(Ws2_32.ADDRESS_FAMILY.AF_INET, out MIB_IPFORWARD_TABLE2 table);
                    //for(var i=0; T)
                    for (var i = 0; i < table.NumEntries; i++)
                    {
                        var row = table.Table[i];
                        if (row.InterfaceLuid.Equals(_adapterLuid))
                        {
                            Console.WriteLine("Start Delete Row [" + i + "] - Metric " + row.Metric);
                            DeleteIpForwardEntry2(ref table.Table[i]);
                        }

                    }

                    for (var i = 0; i < WgConfig.LoctlWireGuardConfig.WgPeerConfigs.Length; i++)
                    {
                        var peerConfig = WgConfig.LoctlWireGuardConfig.WgPeerConfigs[i];
                        MIB_IPFORWARD_ROW2 row;
                        InitializeIpForwardEntry(out row);
                        row.InterfaceLuid = _adapterLuid;

                        row.Metric = 1;

                        var maskedIp = IPNetwork2.Parse("" + peerConfig.allowdIp.V4.Addr, peerConfig.allowdIp.Cidr);

                        row.DestinationPrefix.Prefix.Ipv4.sin_addr = new Ws2_32.IN_ADDR(maskedIp.Network.GetAddressBytes());
                        //row.DestinationPrefix.Prefix.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
                        row.DestinationPrefix.Prefix.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
                        row.DestinationPrefix.PrefixLength = maskedIp.Cidr;

                        row.Protocol = MIB_IPFORWARD_PROTO.MIB_IPPROTO_LOCAL;
                        row.NextHop.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
                        row.NextHop.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;

                        lastError = CreateIpForwardEntry2(ref row);
                        if (lastError.Failed)
                        {
                            //Failed to set default route
                            Console.WriteLine("CreateIpForwardEntry2 [" + i + "] " + lastError.ToString());
                        }
                        else
                        {
                            Console.WriteLine("Set default route [" + i + "] " + lastError.ToString());
                        }

                    }



                    //MIB_UNICASTIPADDRESS_ROW unicastIpAddressRow;
                    InitializeUnicastIpAddressEntry(out MIB_UNICASTIPADDRESS_ROW unicastIpAddressRow);
                    unicastIpAddressRow.InterfaceLuid = _adapterLuid;
                    unicastIpAddressRow.Address.Ipv4.sin_addr = new Ws2_32.IN_ADDR(WgConfig.InterfaceAddress.GetAddressBytes());
                    unicastIpAddressRow.Address.Ipv4.sin_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
                    unicastIpAddressRow.OnLinkPrefixLength = WgConfig.InterfaceNetwork.Cidr;
                    unicastIpAddressRow.DadState = NL_DAD_STATE.IpDadStatePreferred;

                    lastError = CreateUnicastIpAddressEntry(ref unicastIpAddressRow);
                    if (lastError.Failed)
                    {
                        //Failed to set IP address
                        Console.WriteLine("CreateUnicastIpAddressEntry " + lastError.ToString());
                    }
                    else
                    {
                        Console.WriteLine("Set Ip address " + lastError.ToString());
                    }
                    //MIB_IPINTERFACE_ROW ipInterfaceRow;
                    InitializeIpInterfaceEntry(out MIB_IPINTERFACE_ROW ipInterfaceRow);
                    ipInterfaceRow.InterfaceLuid = _adapterLuid;
                    ipInterfaceRow.Family = Ws2_32.ADDRESS_FAMILY.AF_INET;

                    lastError = GetIpInterfaceEntry(ref ipInterfaceRow);

                    if (lastError.Failed)
                    {
                        //Failed to get IP interface
                        Console.WriteLine("GetIpInterfaceEntry " + lastError.ToString());
                    }
                    else
                    {
                        Console.WriteLine("Set Ip address " + lastError.ToString());
                    }

                    ipInterfaceRow.ForwardingEnabled = true;

                    ipInterfaceRow.UseAutomaticMetric = false;
                    ipInterfaceRow.Metric = 0;
                    ipInterfaceRow.NlMtu = WgConfig.InterfaceMtu;
                    ipInterfaceRow.SitePrefixLength = 0;

                    lastError = SetIpInterfaceEntry(ipInterfaceRow);

                    if (lastError.Failed)
                    {
                        //Failed to set metric and MTU
                        Console.WriteLine("SetIpInterfaceEntry " + lastError.ToString());
                    }
                    else
                    {
                        Console.WriteLine("Set Metric and MTU " + lastError.ToString());
                    }

                    foreach (var dnsAddress in WgConfig.DnsAddresses)
                    {
                        Process.Start("netsh.exe", String.Format("interface ipv4 add dnsservers name={0} address={1} validate=no", adaptername, dnsAddress));
                    }

                    _wireGuardAdapter.SetConfiguration(WgConfig);
                    _wireGuardAdapter.SetStateUp();

                    LogInformation("[WireGuardManager] Configuration loaded successfully from file.");
                    return true;
                }
                else
                {
                    LogError("[WireGuardManager] Error parsing configuration file.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                LogError($"[WireGuardManager] Error loading configuration: {ex.Message}");
                return false;
            }
        }

        public istatus status()
        {
            if (_wireGuardAdapter != null)
            {
                istatus s = new istatus();
                var config = _wireGuardAdapter.GetConfiguration();
                if (config != null)
                {
                    foreach (var peer in config.Peers)
                    {
                       s.rx += peer.RxBytes;
                       s.tx += peer.TxBytes;

                    }
                    s.state = _wireGuardAdapter.GetAdapterState();
                    return s;
                }
            }
            return null;

        }

        public async void Disconnect()
        {
            try
            {

                if (_wireGuardAdapter != null)
                {
                    _wireGuardAdapter.CleanupAdapterRoutes(_adapterLuid, msg => LogInformation(msg));
                    LogInformation("WireGuard Adapter 'max0' exists. Bringing it down.");
                    _wireGuardAdapter.SetStateDown();
                    _wireGuardAdapter.Dispose();    // this calls native function freeadapter
                    _wireGuardAdapter = null;

                    // wait 500 ms
                    await Task.Delay(500);

                }
            }
            catch (Exception ex)
            {
                LogError($"[Disconnect] Exception: {ex.Message}");
            }
        }


        public void Dispose()
        {
            if (_wireGuardAdapter != null)
            {
                _wireGuardAdapter.Dispose();
                _wireGuardAdapter = null;
            }
        }
    }
}