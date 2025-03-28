using System;
using Vanara.PInvoke;
using System.Diagnostics;
using System.IO;

namespace MaxVPNService
{
    public sealed class WireGuardManager : IDisposable
    {
        private static WireGuardManager _instance = null;
        private static readonly object _lock = new object();
        private Adapter _wireGuardAdapter;
        private EventLog _eventLog;

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
                if (_wireGuardAdapter == null)
                {
                    _wireGuardAdapter = new Adapter("max0", "WireGuard");
                    Guid adapterGuid = Guid.NewGuid();
                    IpHlpApi.NET_LUID adapterLuid;
                    _wireGuardAdapter.Init(ref adapterGuid, out adapterLuid);
                    LogInformation($"WireGuard Adapter 'max0' initialized with GUID: {adapterGuid} and LUID: {adapterLuid}");
                    return true;
                }
                return true; // Adapter already initialized
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

                // Create a temporary file to store the config content
                string tempFilePath = Path.GetTempFileName();
                try
                {
                    File.WriteAllText(tempFilePath, configFileContent);

                    // Parse the configuration file
                    WgConfig parsedWgConfig; // Declare the output parameter
                    string[] filePaths = new string[] { tempFilePath }; // Create a string array

                    if (_wireGuardAdapter.ParseConfFile(filePaths, out parsedWgConfig))
                    {
                        LogInformation("[WireGuardManager] Configuration loaded successfully from file.");
                        // You might want to examine or use the parsedWgConfig object if needed
                        _wireGuardAdapter.SetStateUp();
                        return true;
                    }
                    else
                    {
                        LogError("[WireGuardManager] Error parsing configuration file.");
                        return false;
                    }
                }
                finally
                {
                    // Ensure the temporary file is deleted
                    if (File.Exists(tempFilePath))
                    {
                        File.Delete(tempFilePath);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"[WireGuardManager] Error loading configuration: {ex.Message}");
                return false;
            }
        }

        public bool Disconnect()
        {
            try
            {
                if (_wireGuardAdapter != null)
                {
                    _wireGuardAdapter.SetStateDown();
                    Dispose();
                    LogInformation("[WireGuardManager] VPN disconnected and adapter removed.");
                    return true;
                }
                LogInformation("[WireGuardManager] No active VPN to disconnect.");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"[WireGuardManager] Error during disconnect: {ex.Message}");
                return false;
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