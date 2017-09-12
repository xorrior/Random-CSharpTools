using System;
using System.Collections.Generic;
using NDesk.Options;
using System.IO;
using System.Runtime.InteropServices;

/// <summary>
/// Author: Chris Ross @xorrior
/// License: BSD3-Clause
/// Purpose: Clone Authenticode or Catalog signatures from one binary to an unsigned binary
/// </summary>

namespace SigPirate
{
    public class Program
    {
        //variables for command line args
        private static string fromFile;
        private static string destinationFile;
        private static bool authenticodeSteal;
        private static bool help = false;

        public static void Main(string[] args)
        {
            OptionSet opts = new OptionSet()
            {
                {"s=|source=","Target file to copy the cert from", (string v) =>  fromFile = v},
                {"d=|destination=","Destination file to copy the cert to", (string v) => destinationFile = v },
                {"a|authenticode", "Copy the authenticode signature from the source binary", v => authenticodeSteal = v != null },
                {"help", "Show the help menu", v => help = v != null }
            };

            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.ToString());
                PrintHelp(opts);
            }

            if (destinationFile == null || fromFile == null || help == true)
            {
                PrintHelp(opts);
                System.Environment.Exit(-1);
            }

            if (!File.Exists(destinationFile) || !File.Exists(fromFile))
                System.Environment.Exit(-1);

            //Get the File offset for the Security Directory entry.
            try
            {
                srcBytes = File.ReadAllBytes(fromFile);
                destBytes = File.ReadAllBytes(destinationFile);
            }
            catch (Exception e)
            {
                Console.WriteLine("Unable to read files: " + e.ToString());
                System.Environment.Exit(-1);
            }

            //If we are just getting the authenticode signature
            if (authenticodeSteal)
            {
                try
                {
                    GetSecurityDirectoryInfo(srcBytes, true);
                    KeyValuePair<bool,string> result = CopyAuthenticodeSignature();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }
            }
        }

        private static unsafe KeyValuePair<bool, string> CopyAuthenticodeSignature()
        {
            //Function for copying the raw data for the authenticode signature
            //Copy the raw bytes for the signature to the destination/target PE.
            if (cert.bCertificate.Length == 0)
                return new KeyValuePair<bool, string>(false, "Source PE bCertificate field is empty");

            byte[] rawSignature = new byte[cert.dwLength];
            Buffer.BlockCopy(srcBytes, (int)secDirRVA, rawSignature, 0, rawSignature.Length);

            byte[] moddedPE = new byte[destBytes.Length + rawSignature.Length];
            Buffer.BlockCopy(destBytes, 0, moddedPE, 0, destBytes.Length);
            Buffer.BlockCopy(rawSignature, 0, moddedPE, destBytes.Length, rawSignature.Length);
            return new KeyValuePair<bool, string>(true, "Successfully copied authenticode signature to target PE");
        }

        private static unsafe void GetSecurityDirectoryInfo(byte[] pe, bool source)
        {
#if DEBUG
            Console.WriteLine("[+] Parsing PE....");
#endif
            
            fixed (byte* buffer = pe)
            {
                uint e_lfanew = *((uint*)(buffer + 60));
                pe_header = (buffer + e_lfanew);
                numberOfSections = *((ushort*)(pe_header + 6));
                ushort machineType = *((ushort*)(pe_header + 4));

                //if everything checks out, continue
                //jmp to the offset for Magic
                byte* magic = (pe_header + 24);
                short magic_val = *((short*)magic);

                if (magic_val == 267) /*x86*/
                {
                    is64 = false;
                }
                else if (magic_val == 523) /*x64*/
                {
                    is64 = true;
                }

#if DEBUG
                Console.WriteLine("[+] x64 PE: " + is64.ToString());
#endif
                optional_hdr = (pe_header + 24);


                //Get the RVA and Size for the SECURITY_DIRECTORY
                if (is64)
                {
                    secDirRVA = *((uint*)(optional_hdr + 144));
                    secDirSize = *((uint*)(optional_hdr + 148));
#if DEBUG 
                    Console.WriteLine("Security Directory Entry VA: " + secDirRVA.ToString("X8"));
                    Console.WriteLine("Security Directory Entry Size: " + secDirSize.ToString("X8"));
#endif
                }
                else
                {
                    secDirRVA = *((uint*)(optional_hdr + 128));
                    secDirSize = *((uint*)(optional_hdr + 132));
#if DEBUG
                    Console.WriteLine("Security Directory Entry VA: " + secDirRVA.ToString("X8"));
                    Console.WriteLine("Security Directory Entry Size: " + secDirSize.ToString("X8"));
#endif
                }

                if (source)
                {
                    //Manually fill out the WIN_CERTIFICATE struct
                    byte* securityDirEntry = (buffer + secDirRVA);
                    cert.dwLength = *((int*)(securityDirEntry));
                    cert.wRevision = *((short*)(securityDirEntry + 4));
                    cert.wCertificateType = *((short*)(securityDirEntry + 6));

                    try
                    {
                        cert.bCertificate = new byte[cert.dwLength - 8];
                        Marshal.Copy((IntPtr)(securityDirEntry + 8), cert.bCertificate, 0, cert.bCertificate.Length);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Could not fill bCertificate field of WIN_CERTIFICATE structure: " + e.ToString());
                    }
                }
                
            }

            Console.WriteLine("[+] Parsed PE for Security Directory Entry");

        }


        //Taken from the ReflectiveInjector Project https://github.com/xorrior/Random-CSharpTools/blob/master/ReflectiveInjector/ReflectiveInjector/Injector.cs
        private unsafe uint RvaToFileOffset(uint dwRva)
        {
            //Relatively copied from: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/LoadLibraryR.c#L31
            IMAGE_SECTION_HEADER section_struct;

            //Helper function to convert the Rva's to file offset for the buffer
            ushort sizeOfOptional_hdr = *((ushort*)(pe_header + 20));
            byte* section_hdr = (optional_hdr + sizeOfOptional_hdr);

            // faster than creating a new byte array to just cast to the structure :(
            section_struct = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((IntPtr)section_hdr, typeof(IMAGE_SECTION_HEADER));
            if (dwRva < section_struct.PointerToRawData)
                return dwRva;

            int i = 0;
            do
            {
                if (dwRva >= section_struct.VirtualAddress && dwRva < (section_struct.VirtualAddress + section_struct.SizeOfRawData))
                    return (dwRva - section_struct.VirtualAddress + section_struct.PointerToRawData);

                //next section
                i++;
                section_hdr = (section_hdr + (i * 40));
                section_struct = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(new IntPtr(section_hdr), typeof(IMAGE_SECTION_HEADER));
            } while (i < numberOfSections);

            return 0;
        }

        

        private static void PrintHelp(OptionSet o)
        {
            Console.Error.WriteLine("Usage: CertClone [options]");
            Console.Error.WriteLine("Options");
            o.WriteOptionDescriptions(Console.Error);
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct _WIN_CERTIFICATE
        {
            [FieldOffset(0)]
            public int dwLength;

            [FieldOffset(4)]
            public short wRevision;

            [FieldOffset(6)]
            public short wCertificateType;

            [FieldOffset(8)]
            public byte[] bCertificate;
        }

        [StructLayout(LayoutKind.Explicit)]
        private unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public UInt16 Characteristics;
        }


        //Class variables
        private static bool is64 = false;
        private static _WIN_CERTIFICATE cert = new _WIN_CERTIFICATE();
        private static unsafe byte* pe_header = null;
        private static unsafe byte* optional_hdr = null;
        private static uint secDirSize = 0;
        private static uint secDirRVA = 0;
        private static ushort numberOfSections;
        private static byte[] srcBytes = null;
        private static byte[] destBytes = null;
    }
}
