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
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static MaxVPN_Win.Form1;

namespace MaxVPN_Win
{

   

    public partial class Form1 : Form
    {        
        public class Region
        {
            public int id { get; set; }
            public string Abbrev { get; set; }
            public string Name { get; set; }
            public string icon { get; set; }
            public List<Location> locations { get; set; }
        }
        public class Location
        {
            public int id { get; set; }
            public int RegionID { get; set; }
            public string name { get; set; }
        }

        public class Server
        {
            public string serverip { get; set; }
            public string serverpublickey { get; set; }
            public string clientip { get; set; }
            public int load { get; set; }
        }
        public class otpResponse
        {
            public string private_key {  get; set; }
            public string public_key { get; set; }
        }
        public class otpMessage
        {
            public string Message { get; set; }
        }

        public AppConfig config;
        public Form1()
        {
            InitializeComponent();
        }

        private async Task<Server> GetServer()
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("X-API-Key", "bbdcb4d8-e260-41b4-826b-98e4f5584563");
                var requestBody = new
                {
                    LocationID = comboBox1.SelectedValue,
                    clientpublickey = config.PublicKey,
                    timeout = 60,
                    firewall = true,
                };
                string json = JsonSerializer.Serialize(requestBody);
                var jsonContent = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(
                    $"{config.Server}/preConnectRegion",
                    jsonContent
                );
                response.EnsureSuccessStatusCode();
                var responseString = await response.Content.ReadAsStringAsync();
                var server = JsonSerializer.Deserialize<Server>(responseString);
                toolStripStatusLabel1.Text = $"ServerIP:{server.serverip} clientIP:{server.clientip} serverpubkey: {server.serverpublickey} load:{server.load}";
                return server;
            }
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            var server = await GetServer();

            string cfg = $@"
[Interface]
PrivateKey = {config.PrivateKey}
Address = {server.clientip}
DNS = 8.8.8.8

[Peer]
PublicKey = {server.serverpublickey}
Endpoint = {server.serverip}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25";

            // Send the connect command to the service
            toolStripStatusLabel1.Text = $"Iniating connection to node at {server.serverip} (IP address copied to the clipboad)";
            Clipboard.SetText(server.serverip);
            string result = await SendCommandAsync("connect", cfg);
            timer1.Start();
        }


        private async Task<string> SendCommandAsync(string command, string config = null)
        {
            try
            {
                var pipeName = "WireGuardInterfacePipe";
                using (var pipeClient = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
                {
                    await pipeClient.ConnectAsync(3000);

                    var writer = new StreamWriter(pipeClient) { AutoFlush = true };
                    var reader = new StreamReader(pipeClient);

                    var message = new PipeMessage
                    {
                        Command = command,
                        Payload = config
                    };

                    string messageJson = JsonSerializer.Serialize(message);

                    await writer.WriteLineAsync(messageJson);
                    string response = await reader.ReadLineAsync();

                    toolStripStatusLabel1.Text = response;

                    // Dispose manually after both are done
                    writer.Dispose();
                    reader.Dispose();

                    return response;
                }
            }
            catch (Exception ex)
            {
                toolStripStatusLabel1.Text = ex.Message;
                return "false";
            }
        }


        private async void button2_Click(object sender, EventArgs e)
        {
            timer1.Stop();
           toolStripStatusLabel1.Text= await SendCommandAsync("disconnect", "");
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private async void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                config = AppConfig.Load();
            }
            catch { 
                config = new AppConfig
                {
                    Server = "https://apigateway-staging.maxbrowser.com.au",
                    Email = "steven@databench.com.au",
                    PrivateKey = "KN1Om0JlvEtC7JZ15jNYzZ4MfF/1dogvxBbiNDby3mc=",
                    PublicKey = "OjrWt/2ftzqkRN620VyuZz0MGzEohjvYw+CBzUcBx34=",
                    ApplicationID = "50f95ac3-96f4-4b12-bf15-bfbd8f8a522a"
                };
                config.Save();
            }
            updateTextBoxes();

            List<Region> regions = await FetchRegions();
            comboBox1.DataSource = null;
            comboBox1.Items.Clear();
            List<Location> allLocations = new List<Location>();
            foreach (var region in regions)
            {
                if (region.locations != null)
                {
                    allLocations.AddRange(region.locations);
                }
            }

            // Set ComboBox data binding
            comboBox1.DataSource = allLocations;
            comboBox1.DisplayMember = "name"; // what the user sees
            comboBox1.ValueMember = "id";     // the underlying value

        }
        private void updateTextBoxes()
        {
            textBox1.Text = config.Server;
            textBox2.Text = config.Email;
            textBox3.Text = config.PrivateKey;
            textBox4.Text = config.PublicKey;
            textBox5.Text = config.ApplicationID;
        }

        private async void button3_Click(object sender, EventArgs e)
        {
            List<Region> regions = await FetchRegions();
            comboBox1.DataSource = null;
            comboBox1.Items.Clear();
            List<Location> allLocations = new List<Location>();
            foreach (var region in regions)
            {
                if (region.locations != null)
                {
                    allLocations.AddRange(region.locations);
                }
            }

            // Set ComboBox data binding
            comboBox1.DataSource = allLocations;
            comboBox1.DisplayMember = "name"; // what the user sees
            comboBox1.ValueMember = "id";     // the underlying value
        }
        private async Task<List<Region>> FetchRegions()
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("X-API-Key", "bbdcb4d8-e260-41b4-826b-98e4f5584563");
                var requestBody = new
                {
                    publickey = textBox4.Text,
                };
                string json = JsonSerializer.Serialize(requestBody);
                var jsonContent = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(
                    $"{config.Server}/getRegions",
                    jsonContent
                );
                response.EnsureSuccessStatusCode();
                var responseString = await response.Content.ReadAsStringAsync();
                var regions = JsonSerializer.Deserialize<List<Region>>(responseString);
                toolStripStatusLabel1.Text = $"{regions.Count} Regions loaded";
                return regions;
            }
        }

        private async void button4_Click(object sender, EventArgs e)
        {
            otpMessage reply = await Login();
            MessageBox.Show(reply.Message);
        }
        private async Task<otpMessage> Login()
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("X-API-Key", "bbdcb4d8-e260-41b4-826b-98e4f5584563");
                var requestBody = new
                {
                    email = config.Email,
                };
                string json = JsonSerializer.Serialize(requestBody);
                var jsonContent = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(
                    $"{config.Server}/login",
                    jsonContent
                );
                response.EnsureSuccessStatusCode();
                var responseString = await response.Content.ReadAsStringAsync();
                var msg = JsonSerializer.Deserialize<otpMessage>(responseString);
                toolStripStatusLabel1.Text = "login request Sent";
                return msg;
            }
        }

        private async void button5_Click(object sender, EventArgs e)
        {
            otpResponse keys = await ValidateOTP(textBox6.Text);
            config.PrivateKey = keys.private_key;
            config.PublicKey = keys.public_key;
            config.Save();
            updateTextBoxes();
        }
        private async Task<otpResponse> ValidateOTP(string otp)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("X-API-Key", "bbdcb4d8-e260-41b4-826b-98e4f5584563");
                var requestBody = new
                {
                    email = config.Email,
                    OTP=otp,
                    application_id=config.ApplicationID
                };
                string json = JsonSerializer.Serialize(requestBody);
                var jsonContent = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(
                    $"{config.Server}/validateOTP",
                    jsonContent
                );
                response.EnsureSuccessStatusCode();
                var responseString = await response.Content.ReadAsStringAsync();
                var keys = JsonSerializer.Deserialize<otpResponse>(responseString);
                toolStripStatusLabel1.Text = "OTP Validated";
                return keys;
            }
        }
        private void textBox5_TextChanged(object sender, EventArgs e)
        {
            config.ApplicationID=textBox5.Text;
            config.Save();
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            config.Email=textBox2.Text;
            config.Save();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            config.Server=textBox1.Text;
            config.Save();
        }

        private async void timer1_Tick(object sender, EventArgs e)
        {
            string result = await SendCommandAsync("status", "");
            toolStripStatusLabel1.Text=result;

        }
    }
}
