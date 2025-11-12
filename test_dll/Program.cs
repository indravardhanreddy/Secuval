using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("secureapis.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr secureapis_create_config(IntPtr configJson);

    static void Main(string[] args)
    {
        try
        {
            Console.WriteLine("Testing DLL load...");
            var configJson = Marshal.StringToHGlobalAnsi("{}");
            var result = secureapis_create_config(configJson);
            Console.WriteLine($"Success! Result: {result}");
            Marshal.FreeHGlobal(configJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}