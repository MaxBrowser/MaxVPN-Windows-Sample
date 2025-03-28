These resources are used by the MAX VPN service

The main implementation being used is WireguardNT this is a High performance in-kernel WireGuard implementation for Windows, compiled as a Dynamically linked library
The files are available from https://download.wireguard.com/wireguard-nt/

the available packages have only C++ wireguard.h defintitions for interfacing with the dll, so we have created our own wireguard.cs C# class library to 
interact with the dll.