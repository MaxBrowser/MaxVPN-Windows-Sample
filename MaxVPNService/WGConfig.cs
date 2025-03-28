﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using MaxVPNService;

namespace MaxVPNService
{
    public class WgConfig
    {
        public loctlWireGuardConfig LoctlWireGuardConfig;
        public IPAddress InterfaceAddress { get; set; }
        public IPNetwork2 InterfaceNetwork { get; set; }
        public IPAddress[] DnsAddresses { get; set; }

        public ushort InterfaceMtu = 1420;
        public ushort InterfaceListenPort { get; set; }

        public ConfigBuffer ConfigBuffer;
        public WgConfig()
        {
            LoctlWireGuardConfig = new loctlWireGuardConfig();
        }
    }
}
