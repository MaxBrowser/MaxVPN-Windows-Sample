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
using static MaxVPNService.WireGuardDllWrapper;

namespace MaxVPNService
{
    public partial class MaxVPNService : ServiceBase
    {
        private CancellationTokenSource _cancellationTokenSource;
        private Task _pipeServerTask;      
        private Guid guid;
        private IntPtr adapterHandle;

        public 
            MaxVPNService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            _cancellationTokenSource = new CancellationTokenSource();

            _pipeServerTask = Task.Run(() => StartPipeServer(_cancellationTokenSource.Token));

            // Optional logging
            EventLog.WriteEntry("MaxVPNService started and pipe server is listening.", EventLogEntryType.Information);
          
        }

        protected override void OnStop()
        {
            _cancellationTokenSource.Cancel();

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

                            bool result = false;

                            switch (message.Command.ToLower())
                            {
                                case "connect":
                                    result = HandleConnect(message.Payload);
                                    break;
                                case "disconnect":
                                    result = HandleDisconnect();
                                    break;
                                default:
                                    break;
                            }

                            await writer.WriteLineAsync(result.ToString().ToLower());

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

        private bool HandleConnect(string payload)
        {
            try
            {
                adapterHandle = WireGuardManager.InitializeWireGuardAdapter("wg0");
                WireGuardDllWrapper.SetLogger(MyLoggerCallback);
                WireGuardConfig config = JsonSerializer.Deserialize<WireGuardConfig>(payload);
                if (config == null)
                    return false;
                WireGuardManager.ConfigureAdapter(adapterHandle, config);

                // TODO: Add your VPN config logic here!
                EventLog.WriteEntry($"[Connect] Interface: {config.Interface.Address} - Peers: {config.Peers.Count}", EventLogEntryType.Information);


                return true;
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry($"[Connect] Error: {ex.Message}", EventLogEntryType.Error);
                return false;
            }
        }

        private bool HandleDisconnect()
        {
            try
            {
                // TODO: Add your VPN disconnect logic here!
                EventLog.WriteEntry("[Disconnect] VPN disconnected.", EventLogEntryType.Information);

                return true;
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry($"[Disconnect] Error: {ex.Message}", EventLogEntryType.Error);
                return false;
            }
        }
        private static void MyLoggerCallback(WIREGUARD_LOGGER_LEVEL level, ulong timestamp, string message)
        {
            Console.WriteLine($"[{level}] {DateTime.FromFileTimeUtc((long)timestamp)}: {message}");
        }
    }

    // WireGuardConfig + Peer + Interface classes go here.
}
