using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MaxVPNService
{
    public class WireGuardLoader
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        public static void LoadWireGuardDll()
        {
            string dllPath = GetArchitectureSpecificDllPath();
            IntPtr dllHandle = LoadLibrary(dllPath);

            if (dllHandle == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                Console.WriteLine($"Failed to load the DLL from {dllPath}. Error Code: {errorCode}");
                // Handle errors as needed (throw exception, exit, etc.)
                return;
            }

            Console.WriteLine($"Successfully loaded {dllPath}");
            // Proceed with other initializations or operations that depend on the DLL
        }

        private static string GetArchitectureSpecificDllPath()
        {
            string resourcesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "wireguard-nt", "bin");
            string archPath = string.Empty;

            switch (Environment.Is64BitProcess)
            {
                case true when RuntimeInformation.ProcessArchitecture == Architecture.Arm64:
                    archPath = "arm64";
                    break;
                case true:
                    archPath = "amd64";
                    break;
                case false when RuntimeInformation.ProcessArchitecture == Architecture.Arm:
                    archPath = "arm";
                    break;
                case false:
                    archPath = "x86";
                    break;
            }

            return Path.Combine(resourcesPath, archPath, "wireguard.dll");
        }

    }

}
