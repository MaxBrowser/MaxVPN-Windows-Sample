using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO.Pipes;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MaxVPN_Win
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            //WireGuardConfigBuilder configBuilder = new WireGuardConfigBuilder();
            //WireGuardConfig wireGuardConfig = configBuilder
            //    .SetInterface(
            //        privateKey: "ECje7R3ve2B9Wk2cF/BV+ziMXyhpwFteu47wfv5RKmA=",
            //        address: "10.53.0.14/32",
            //        dns: "8.8.8.8"
            //    )
            //    .AddPeer(
            //        publicKey: "kv0fJ7TeiOGflPZKYAxPNkesdf+W9qe+p2YjHQo41xo=",
            //        endpoint: "67.219.108.79:51820",
            //        allowedIPs: "0.0.0.0/0, ::/0",
            //        persistentKeepalive: 25
            //    )
            //    .Build();
            string config = $"[Interface]\r\nPrivateKey = ECje7R3ve2B9Wk2cF/BV+ziMXyhpwFteu47wfv5RKmA=\r\nAddress = 10.53.0.14/32\r\nDNS = 8.8.8.8\r\n\r\n[Peer]\r\nPublicKey = kv0fJ7TeiOGflPZKYAxPNkesdf+W9qe+p2YjHQo41xo=\r\nEndpoint = 67.219.108.79:51820\r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nPersistentKeepalive = 25";
            // Send the connect command to the service
            string result = await SendCommandAsync("connect", config);

            // Show result in a message box or update your UI here
            //MessageBox.Show($"Connect command result: {result}");
        }


        private async Task<string> SendCommandAsync(string command, string config = null)
        {
            try
            {
                var pipeName = "WireGuardInterfacePipe";
                using (var pipeClient = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
                {
                    await pipeClient.ConnectAsync(3000); // Timeout in ms
                    using (var writer = new StreamWriter(pipeClient) { AutoFlush = true })
                    using (var reader = new StreamReader(pipeClient))
                    {                      
                        var message = new PipeMessage
                        {
                            Command = command,
                            Payload = config
                        };

                        string messageJson = JsonSerializer.Serialize(message);

                        // Send the command message
                        await writer.WriteLineAsync(messageJson);

                        // Wait for a response from the service
                        string response = await reader.ReadLineAsync();
                        return response;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error sending command: {ex.Message}");
                return "false";
            }
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            string result = await SendCommandAsync("disconnect", "");
        }
    }
}
