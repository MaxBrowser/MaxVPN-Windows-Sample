using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

public class WireGuardConfig
{
    [JsonPropertyName("interface")]
    public Interface Interface { get; set; }

    [JsonPropertyName("peers")]
    public List<Peer> Peers { get; set; } = new List<Peer>();
}

public class Interface
{
    [JsonPropertyName("privateKey")]
    public string PrivateKey { get; set; }

    [JsonPropertyName("address")]
    public string Address { get; set; }

    [JsonPropertyName("dns")]
    public string DNS { get; set; }
}

public class Peer
{
    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; }

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; }

    [JsonPropertyName("allowedIPs")]
    public string AllowedIPs { get; set; }

    [JsonPropertyName("persistentKeepalive")]
    public int PersistentKeepalive { get; set; }
}

public class WireGuardConfigBuilder
{
    private Interface _interface;
    private List<Peer> _peers = new List<Peer>();

    // Set Interface Details
    public WireGuardConfigBuilder SetInterface(string privateKey, string address, string dns)
    {
        _interface = new Interface
        {
            PrivateKey = privateKey,
            Address = address,
            DNS = dns
        };
        return this;
    }

    // Add a Peer
    public WireGuardConfigBuilder AddPeer(string publicKey, string endpoint, string allowedIPs, int persistentKeepalive = 0)
    {
        var peer = new Peer
        {
            PublicKey = publicKey,
            Endpoint = endpoint,
            AllowedIPs = allowedIPs,
            PersistentKeepalive = persistentKeepalive
        };

        _peers.Add(peer);
        return this;
    }

    // Final Build Method
    public WireGuardConfig Build()
    {
        if (_interface == null)
            throw new InvalidOperationException("Interface section must be defined before building the config.");

        return new WireGuardConfig
        {
            Interface = _interface,
            Peers = _peers
        };
    }
}

