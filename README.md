## MaxVPNService 
 custom Windows Service that manages a WireGuard VPN interface using a secure, background daemon approach. It allows clients to:

- Connect to a WireGuard server with a specified configuration

- Disconnect and safely tear down the adapter

- Monitor transmission (tx) and reception (rx) statistics

- Interact via a named pipe (WireGuardInterfacePipe)

## ⚙️ Requirements

- Windows 10 or later (Admin access required for setup)

- WireGuard DLL (wireguard.dll) available and accessible by the service

- .NET Framework 4.7.2+ or .NET Core/Windows-compatible runtime

- Vanara.PInvoke library (bundled into the project or installed via NuGet)

## 🚀 Installation

1. Compile the Service

Use Visual Studio or dotnet build to compile the project into a Windows Service executable.

2. Install the Service

Run the following in Command Prompt as Administrator:

```sc create MaxVPNService binPath= "C:\Path\To\MaxVPNService.exe" ```

Or use InstallUtil:

```"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" MaxVPNService.exe ```

3. Start the Service

```net start MaxVPNService ```

You should see a log entry in Event Viewer:
 "MaxVPNService started and pipe server is listening."

## 🔌 Communication – Named Pipe API

The service listens on a named pipe called:

```\\.\pipe\WireGuardInterfacePipe ```

Clients can connect to this pipe and send JSON-encoded commands, one per line.

## 📤 Commands

#### ✅ Connect

```{   "Command": "connect",   "Payload": "[WireGuardConfig as string]" } ```

Payload must be a valid WireGuard configuration file content (INI format, as string).

#### ❌ Disconnect

```{   "Command": "disconnect" } ```

Will tear down the adapter and clean up routing entries.

#### 📈 Status

```{   "Command": "status" } ```

Returns JSON like:

```{   "rx": 123456,   "tx": 654321 } ``

#### 📥 Response Values

- "Connected" — on successful connection

- "Disconnected" — on successful disconnection

- "false" — on invalid command or empty payload

- JSON string — on status with stats

- Error string — if an exception occurs during execution

## 🔁 Service Lifecycle

### Startup:

- Loads wireguard.dll

- Starts named pipe listener

- Starts watchdog (disconnects if no status check for 60s)

### Shutdown:

- Cancels background tasks

- Disposes adapter if in use

- Logs shutdown to Windows Event Viewer

## 🧪 Example Named Pipe Client (nodejs)


```
const net = require('net');
const PIPE_NAME = 'WireGuardInterfacePipe';
const PIPE_PATH = `\\\\.\\pipe\\${PIPE_NAME}`;
// Example command: Get status
const message = {
  Command: 'status'
  // Or for connect:
  // Command: 'connect',
  // Payload: '[WireGuard config string here]'
};
// Convert to JSON line-delimited
const payload = JSON.stringify(message) + '\n';
const client = net.createConnection(PIPE_PATH, () => {
  console.log('✅ Connected to MaxVPNService pipe.');
  client.write(payload);
});
client.on('data', (data) => {
  console.log('📥 Response from service:', data.toString().trim());
  client.end();
});
client.on('end', () => {
  console.log('🔌 Disconnected from service.');
});
client.on('error', (err) => {
  console.error('❌ Pipe connection error:', err.message);
});
```


## 📁 Logs

All logs are sent to Windows Event Viewer under the Application log source as MaxVPNService.

## 📚 WireGuard Config Format

The payload for the connect command must look like:


```
[Interface]
PrivateKey = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Address = 10.0.0.2/24
ListenPort = 51820
DNS = 1.1.1.1
[Peer]
PublicKey = yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
 ```
