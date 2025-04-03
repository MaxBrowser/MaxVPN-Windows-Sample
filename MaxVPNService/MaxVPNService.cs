using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Vanara.PInvoke;

namespace MaxVPNService
{
    public partial class MaxVPNService : ServiceBase
    {
        private CancellationTokenSource _cancellationTokenSource;
        private Task _pipeServerTask;      
        private Adapter _wireGuardAdapter;
        private DateTime _lastStatusCheck;
        private int timeout = 60;

        public 
            MaxVPNService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            WireGuardManager.Instance.SetEventLog(this.EventLog);
            _cancellationTokenSource = new CancellationTokenSource();           
            _pipeServerTask = Task.Run(() => StartPipeServer(_cancellationTokenSource.Token));
            Task.Run(() => StartWatchdog(_cancellationTokenSource.Token)); // 👈 watchdog


            // Optional logging
            EventLog.WriteEntry("MaxVPNService started and pipe server is listening.", EventLogEntryType.Information);
          
        }


        protected override void OnStop()
        {
            _cancellationTokenSource.Cancel();
            if (_wireGuardAdapter != null)
            {
                _wireGuardAdapter.Dispose();
                _wireGuardAdapter = null; // Optionally set it to null after disposing
            }

            try
            {
                _pipeServerTask.Wait();
            }
            catch (AggregateException)
            {
                // Handle if necessary
            }

            // Optional logging
            EventLog.WriteEntry("MaxVPNService stopped and pipe server was shut down.", EventLogEntryType.Information);
        }


        private async Task StartWatchdog(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var elapsed = DateTime.Now - _lastStatusCheck;
                    if (elapsed.TotalSeconds > timeout)
                    {
                        EventLog.WriteEntry($"Watchdog: No status check for {elapsed.TotalSeconds} seconds. Disconnecting VPN.", EventLogEntryType.Warning);
                        HandleDisconnect();
                    }
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry($"Watchdog error: {ex.Message}", EventLogEntryType.Error);
                }

                await Task.Delay(5000, cancellationToken); // check every 5 seconds
            }
        }

        private async Task StartPipeServer(CancellationToken cancellationToken)
        {
            var pipeName = "WireGuardInterfacePipe";
            while (!cancellationToken.IsCancellationRequested)
            {
                PipeSecurity pipeSecurity = new PipeSecurity();
                pipeSecurity.AddAccessRule(new PipeAccessRule("Everyone", PipeAccessRights.FullControl, AccessControlType.Allow));
                pipeSecurity.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().Owner, PipeAccessRights.FullControl, AccessControlType.Allow));
                using (NamedPipeServerStream pipeServer = new NamedPipeServerStream(pipeName, PipeDirection.InOut, -1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, pipeSecurity))

                {
                    try
                    {
                        // Wait for connection with cancellation
                        var waitTask = pipeServer.WaitForConnectionAsync(cancellationToken);

                        // Wait until connection or cancellation
                        await waitTask;

                        if (!pipeServer.IsConnected)
                            continue;

                        using (var reader = new StreamReader(pipeServer))
                        using (var writer = new StreamWriter(pipeServer) { AutoFlush = true })
                        {
                            // Read message from client
                            string messageJson = await reader.ReadLineAsync();

                            if (string.IsNullOrWhiteSpace(messageJson))
                            {
                                await writer.WriteLineAsync("false");
                                continue;
                            }

                            var message = JsonSerializer.Deserialize<PipeMessage>(messageJson);

                            if (message == null)
                            {
                                await writer.WriteLineAsync("false");
                                continue;
                            }

                            string result = "";

                            switch (message.Command.ToLower())
                            {
                                case "connect":
                                    result = HandleConnect(message.Payload);
                                    break;
                                case "disconnect":
                                    result = HandleDisconnect();
                                    break;
                                case "status":
                                    result = HandleStatus();
                                    break;
                                default:
                                    break;
                            }

                            await writer.WriteLineAsync(result);

                            // Optional: log actions
                            EventLog.WriteEntry($"Command '{message.Command}' handled with result: {result}", EventLogEntryType.Information);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // Gracefully handle cancellation
                        EventLog.WriteEntry("Pipe server operation cancelled.", EventLogEntryType.Information);
                    }
                    catch (Exception ex)
                    {
                        EventLog.WriteEntry($"Pipe server error: {ex.Message}", EventLogEntryType.Error);
                    }
                }
            }
        }

        private string HandleConnect(string payload)
        {
            try
            {
                if(WireGuardManager.Instance.LoadConfiguration(payload))
                {
                    _lastStatusCheck= DateTime.Now;
                    return "Connected";
                }
                else
                {
                    return "connection failed";
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry($"[Connect] Error: {ex.Message}", EventLogEntryType.Error);
                return $"[Connect] Error: {ex.Message}";
            }
        }

        private string HandleStatus()
        {
            _lastStatusCheck = DateTime.Now;
            if (WireGuardManager.Instance != null)
            {
                istatus s = WireGuardManager.Instance.status();
                var myData = new
                {
                    rx = s.rx,
                    tx = s.tx,
                };
                return JsonSerializer.Serialize(myData);
            }
            else
            {
                return string.Empty;
            }

        }

        private string HandleDisconnect()
        {
            try
            {
                WireGuardManager.Instance.Disconnect();
                
                return "disconnected";
                
                
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry($"[Disconnect] Error: {ex.Message}", EventLogEntryType.Error);
                return $"[Disconnect] Error: {ex.Message}";
            }
        }
      
    }

    // WireGuardConfig + Peer + Interface classes go here.
}
