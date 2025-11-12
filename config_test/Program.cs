using SecureAPIs;
using System;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Testing SecureAPIs JSON Configuration Loading...");

        try
        {
            // Test 1: Load from JSON file
            Console.WriteLine("\n1. Loading configuration from JSON file...");
            var config = SecureAPIsConfig.Load("../bindings/csharp/secureapis.config.json");

            Console.WriteLine($"Rate Limit Requests: {config.RateLimitRequests}");
            Console.WriteLine($"Rate Limit Window: {config.RateLimitWindowSeconds}s");
            Console.WriteLine($"Enable Rate Limiting: {config.EnableRateLimiting}");
            Console.WriteLine($"Enable Input Validation: {config.EnableInputValidation}");
            Console.WriteLine($"Enable Threat Detection: {config.EnableThreatDetection}");
            Console.WriteLine($"Log Level: {config.LogLevel}");

            // Test 2: Load default configuration
            Console.WriteLine("\n2. Loading default configuration...");
            var defaultConfig = SecureAPIsConfig.Load();

            Console.WriteLine($"Default Rate Limit: {defaultConfig.RateLimitRequests}");

            // Test 3: Test SecureAPIs instance creation
            Console.WriteLine("\n3. Creating SecureAPIs instance...");
            using (var secureAPIs = new SecureAPIs.SecureAPIs(config))
            {
                Console.WriteLine("SecureAPIs instance created successfully!");
            }

            Console.WriteLine("\n✅ All tests passed! JSON configuration loading works correctly.");

        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Test failed: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
        }
    }
}