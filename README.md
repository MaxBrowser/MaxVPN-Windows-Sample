
# MaxVPN Client

This is the client application for interacting with the MaxVPN Windows Service via named pipe communication.  
The service component is now maintained separately at:  
🔗 **[MaxWindowsVPNService Repository](https://github.com/MaxBrowser/MaxWindowsVPNService.git)**

The client is used to:

- Connect to a WireGuard server using a configuration file  
- Disconnect and tear down the VPN adapter  
- Query the current VPN connection status (rx/tx stats)  
- Send commands to the service via a secure named pipe

---

## ⚙️ Requirements

- Windows 10 or later  
- The MaxVPNService must already be installed and running (see linked repo)  
- Node.js (optional, for using or testing the example client)  

---

## 📡 Communication – Named Pipe API

The client communicates with the VPN service using the following named pipe:

```
\\.\pipe\maxVPNInteractiveService
```

All commands are sent in **JSON** format (one object per line). Responses are plain text or JSON depending on the command.

---

## 📤 Supported Commands

### ✅ Connect

```
{
  "Command": "connect",
  "Payload": "[WireGuardConfig as string]"
}
```

- Payload must be a full WireGuard configuration in INI format as a single string.

### ❌ Disconnect

```
{
  "Command": "disconnect"
}
```

- Safely shuts down the VPN interface and removes routing rules.

### 📈 Status

```
{
  "Command": "status"
}
```

- Returns a response like:

```
{
  "rx": 123456,
  "tx": 654321
}
```

---

## 📥 Response Values

| Response           | Meaning                                      |
|--------------------|----------------------------------------------|
| `"Connected"`      | Successful connection established            |
| `"Disconnected"`   | VPN interface was successfully removed       |
| `"false"`          | Invalid command or malformed payload         |
| JSON object        | Status query result with rx/tx values        |
| Error string       | If an exception occurs inside the service    |

---

## 🧪 Example Node.js Client

```js
const net = require('net');
const PIPE_NAME = 'maxVPNInteractiveService';
const PIPE_PATH = `\\\\.\\pipe\\${PIPE_NAME}`;

const message = {
  Command: 'status'
  // or:
  // Command: 'connect',
  // Payload: '[WireGuard config string here]'
};

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

---

## 📚 WireGuard Config Format

Example payload for the `connect` command:

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

---

## 📎 Additional Notes

- Ensure the service is running and accessible before attempting client commands.
- You can view logs related to the VPN service in **Windows Event Viewer** under the `Application` log (source: `MaxVPNService`).
