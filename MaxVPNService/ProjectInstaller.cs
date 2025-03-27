using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace MaxVPNService
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : Installer
    {
        private ServiceProcessInstaller serviceProcessInstaller;
        private ServiceInstaller serviceInstaller;

        public ProjectInstaller()
        {
            serviceProcessInstaller = new ServiceProcessInstaller();
            serviceInstaller = new ServiceInstaller();

            // Set the account type under which the service will run
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;

            // Set the service properties
            serviceInstaller.ServiceName = "MaxVPNService";
            serviceInstaller.DisplayName = "Max VPN Service";
            serviceInstaller.Description = "Service to manage WireGuard VPN connections via named pipes.";
            serviceInstaller.StartType = ServiceStartMode.Automatic;

            // Add installers to collection (these are processed by InstallUtil)
            Installers.Add(serviceProcessInstaller);
            Installers.Add(serviceInstaller);
        }
    }
}
