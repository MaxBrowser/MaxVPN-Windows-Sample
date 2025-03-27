using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class PipeMessage
{
    public string Command { get; set; } // e.g., "connect", "disconnect"
    public string Payload { get; set; } // e.g., JSON-encoded config (optional)
}
