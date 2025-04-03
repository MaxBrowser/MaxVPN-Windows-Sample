using System;
using System.IO;

public class AppConfig
{
    public string Server { get; set; }
    public string Email { get; set; }
    public string PrivateKey { get; set; }
    public string PublicKey { get; set; }
    public string ApplicationID { get; set; }

    private const string ConfigFileName = "config.txt";

    public void Save(string filePath = ConfigFileName)
    {
        using (StreamWriter writer = new StreamWriter(filePath))
        {
            writer.WriteLine($"Server={Server}");
            writer.WriteLine($"Email={Email}");
            writer.WriteLine($"PrivateKey={PrivateKey}");
            writer.WriteLine($"PublicKey={PublicKey}");
            writer.WriteLine($"ApplicationID={ApplicationID}");
        }
    }
    
    public static AppConfig Load(string filePath = ConfigFileName)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Configuration file '{filePath}' not found.");

        AppConfig config = new AppConfig();

        string[] lines = File.ReadAllLines(filePath);

        foreach (var line in lines)
        {
            var parts = line.Split(new char[] { '=' }, 2);
            if (parts.Length != 2)
                continue; // skip invalid lines

            var key = parts[0].Trim();
            var value = parts[1].Trim();

            switch (key)
            {
                case "Server":
                    config.Server = value;
                    break;
                case "Email":
                    config.Email = value;
                    break;
                case "PrivateKey":
                    config.PrivateKey = value;
                    break;
                case "PublicKey":
                    config.PublicKey = value;
                    break;
                case "ApplicationID":
                    config.ApplicationID = value;
                    break;
            }
        }

        return config;
    }
}