using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;

namespace ReflectiveLoader
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if(args.Length < 2)
            {
                //Print help
            }

            string flag = args[0];
            string option = args[1];


            if (flag == "--enc_string")
            {
                raw = Convert.FromBase64String(option);
            }
            else if(flag == "--embedded")
            {

            }
            else if(flag == "--file")
            {
                raw = File.ReadAllBytes(option);
                IntPtr address;
                if (GetInfo())
                    address = Load();

                Console.WriteLine("Done");
            }
        }

        public unsafe static bool GetInfo()
        {
            fixed (byte* buffer = raw)
            {
                uint e_lfanew = *((uint*)(buffer + 60));
                nt_header = (buffer + e_lfanew);
                numberOfsections = *((ushort*)(nt_header + 6));
                ushort machineType = *((ushort*)(nt_header + 4));

#if DEBUG
                Console.WriteLine("[+] Parsing PE");
#endif

                if (machineType == 0x8664)
                    is64 = true;
                else if (machineType == 0x014c)
                    is64 = false;

#if DEBUG 
                Console.WriteLine("[+] Is 64 bit: " + is64.ToString());
#endif

                byte* magic = (nt_header + 24);
                short magic_val = *((short*)magic);
                optional_header = (nt_header + 24);
                addressOfEntryPoint = *((uint*)(optional_header + 16));
                sizeOfOptionalHeader = *(ushort*)(nt_header + 20);
                imageSize = *((uint*)(optional_header + 56));

                if (is64)
                {
                    ulong preferred_address = *((ulong*)(optional_header + 24));
                    export_tbl_rva = *(uint*)(optional_header + 112);
                    export_tbl_size = *(uint*)(optional_header + 116);
                    import_tbl_rva = *(uint*)(optional_header + 120);
                    import_tbl_size = *(uint*)(optional_header + 124);
                    basereloc_tbl_rva = *(uint*)(optional_header + 152);
                    basereloc_tbl_size = *(uint*)(optional_header + 156);
                }
                else
                {
                    preferred_address = *((uint*)(optional_header + 28));
                    export_tbl_rva = *(uint*)(optional_header + 96);
                    export_tbl_size = *(uint*)(optional_header + 100);
                    import_tbl_rva = *(uint*)(optional_header + 104);
                    import_tbl_size = *(uint*)(optional_header + 108);
                    basereloc_tbl_rva = *(uint*)(optional_header + 136);
                    basereloc_tbl_size = *(uint*)(optional_header + 140);
                }

                return true;
            }
        }

        public unsafe static IntPtr Load()
        {
            // Load the image into memory
            Win32.IMAGE_SECTION_HEADER img_sct_hdr;
            fixed(byte* buffer = raw)
            {
                peHandle = Win32.VirtualAlloc(IntPtr.Zero, imageSize, 0x1000, 0x40);
                //Copy sections to memory

                for (int i = 0; i < numberOfsections; i++)
                {
                    byte* sectionPtr = (optional_header + sizeOfOptionalHeader + (i * Marshal.SizeOf(typeof(Win32.IMAGE_SECTION_HEADER))));
                    img_sct_hdr = (Win32.IMAGE_SECTION_HEADER)Marshal.PtrToStructure((IntPtr)sectionPtr, typeof(Win32.IMAGE_SECTION_HEADER));
                    IntPtr sectionAddress = Win32.VirtualAlloc(new IntPtr(peHandle.ToInt64() + img_sct_hdr.VirtualAddress), img_sct_hdr.SizeOfRawData, 0x1000, 0x40);
                    Marshal.Copy(raw, (int)img_sct_hdr.PointerToRawData, sectionAddress, (int)img_sct_hdr.SizeOfRawData);

#if DEBUG
                    Console.WriteLine("Section {0}, Copied To {1}", new string(img_sct_hdr.Name), sectionAddress.ToString("X8"));
#endif
                }

                //Base relocation
                IntPtr currentBase = peHandle;
                long delta;

                if (is64) delta = (long)(currentBase.ToInt64() - (long)preferred_address);
                else delta = (int)(currentBase.ToInt32() - (int)preferred_address);

                IntPtr relocationTable = (IntPtr)(peHandle.ToInt64() + basereloc_tbl_rva);

                Win32.IMAGE_BASE_RELOCATION relocationEntry = new Win32.IMAGE_BASE_RELOCATION();
                relocationEntry = (Win32.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(Win32.IMAGE_BASE_RELOCATION));

                int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(Win32.IMAGE_BASE_RELOCATION));
                IntPtr nextEntry = relocationTable;
                int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
                IntPtr offset = relocationTable;

                while (true)
                {
                    Win32.IMAGE_BASE_RELOCATION relocationNextEntry = new Win32.IMAGE_BASE_RELOCATION();
                    IntPtr x = (IntPtr)(relocationTable.ToInt64() + sizeofNextBlock);
                    relocationNextEntry = (Win32.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(Win32.IMAGE_BASE_RELOCATION));

                    IntPtr dest = (IntPtr)(peHandle.ToInt64() + relocationEntry.VirtualAdress);

                    for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                    {
                        IntPtr patchAddr;
                        UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));

                        UInt16 type = (UInt16)(value >> 12);
                        UInt16 fixup = (UInt16)(value & 0xfff);

                        switch (type)
                        {
                            case 0x0:
                                break;
                            case 0x3:
                                patchAddr = (IntPtr)(dest.ToInt64() + fixup);
                                //Add Delta To Location.                            
                                int originalx86Addr = Marshal.ReadInt32(patchAddr);
                                Marshal.WriteInt32(patchAddr, originalx86Addr + (int)delta);
                                break;
                            case 0xA:
                                patchAddr = (IntPtr)(dest.ToInt64() + fixup);
                                //Add Delta To Location.
                                long originalAddr = Marshal.ReadInt64(patchAddr);
                                Marshal.WriteInt64(patchAddr, originalAddr + delta);
                                break;

                        }

                        offset = (IntPtr)(relocationTable.ToInt64() + sizeofNextBlock);
                        sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                        relocationEntry = relocationNextEntry;

                        nextEntry = (IntPtr)(nextEntry.ToInt64() + sizeofNextBlock);

                        if (relocationNextEntry.SizeOfBlock == 0) break;
                    }
                }


            }

            // Load all the imports
            IntPtr z;
            IntPtr oa1;
            int oa2;
            byte* sectPtr = (optional_header + sizeOfOptionalHeader + (1 * Marshal.SizeOf(typeof(Win32.IMAGE_SECTION_HEADER))));
            img_sct_hdr = (Win32.IMAGE_SECTION_HEADER)Marshal.PtrToStructure((IntPtr)sectPtr, typeof(Win32.IMAGE_SECTION_HEADER));

            
            z = (IntPtr)(peHandle.ToInt64() + img_sct_hdr.VirtualAddress);
            oa1 = (IntPtr)(peHandle.ToInt64() + import_tbl_rva);
            oa2 = Marshal.ReadInt32((IntPtr)(oa1.ToInt64() + 16));

            IntPtr threadStart;
            IntPtr hThread;
            if (is64)
            {
                int j = 0;
                while (true)
                {
                    IntPtr a1 = (IntPtr)(peHandle.ToInt64() + ((20 * j) + import_tbl_rva));
                    int entryLength = Marshal.ReadInt32((IntPtr)(a1.ToInt64() + 16));
                    IntPtr a2 = (IntPtr)(peHandle.ToInt64() + img_sct_hdr.VirtualAddress + (entryLength - oa2));
                    IntPtr dllNamePTR = (IntPtr)(peHandle.ToInt64() + Marshal.ReadInt32((IntPtr)(a1.ToInt64() + 12)));
                    string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                    if (DllName == "") break;

                    IntPtr handle = Win32.LoadLibrary(DllName);
#if DEBUG 
                    Console.WriteLine("Loaded {0}", DllName);
#endif
                    int k = 0;
                    while (true)
                    {
                        IntPtr dllFuncNamePTR = (IntPtr)(peHandle.ToInt64() + Marshal.ReadInt32(a2));
                        string DllFuncName = Marshal.PtrToStringAnsi((IntPtr)(dllFuncNamePTR.ToInt64() + 2));
                        //Console.WriteLine("Function {0}", DllFuncName);
                        IntPtr funcAddy = Win32.GetProcAddress(handle, DllFuncName);
                        Marshal.WriteInt64(a2, (long)funcAddy);
                        a2 = (IntPtr)(a2.ToInt64() + 8);
                        if (DllFuncName == "") break;
                        k++;
                    }
                    j++;
                }
            }
            else
            {
                int j = 0;
                while (true)
                {
                    IntPtr a1 = (IntPtr)(peHandle.ToInt64() + ((20 * j) + import_tbl_rva));
                    int entryLength = Marshal.ReadInt32((IntPtr)(a1.ToInt64() + 16));
                    IntPtr a2 = (IntPtr)(peHandle.ToInt64() + img_sct_hdr.VirtualAddress + (entryLength - oa2));
                    IntPtr dllNamePTR = (IntPtr)(peHandle.ToInt64() + Marshal.ReadInt32((IntPtr)(a1.ToInt64() + 12)));
                    string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                    if (DllName == "") break;

                    IntPtr handle = Win32.LoadLibrary(DllName);
#if DEBUG
                    Console.WriteLine("Loaded {0}", DllName);
#endif
                    int k = 0;
                    while (true)
                    {
                        IntPtr dllFuncNamePTR = (IntPtr)(peHandle.ToInt64() + Marshal.ReadInt32(a2));
                        string DllFuncName = Marshal.PtrToStringAnsi((IntPtr)(dllFuncNamePTR.ToInt64() + 2));
                        IntPtr funcAddy = Win32.GetProcAddress(handle, DllFuncName);
                        Marshal.WriteInt32(a2, (int)funcAddy);
                        a2 = (IntPtr)(a2.ToInt64() + 4);
                        if (DllFuncName == "") break;
                        k++;
                    }
                    j++;
                }
            }
#if DEBUG
            Console.WriteLine("Calling DllMain");
#endif

            threadStart = (IntPtr)(peHandle.ToInt64() + addressOfEntryPoint);
            Win32.dm dllMain = (Win32.dm)Marshal.GetDelegateForFunctionPointer(threadStart, typeof(Win32.dm));
            dllMain(peHandle, 0, IntPtr.Zero);

            return peHandle;
            //Call function export
        }

        /*public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {

        }*/

        private static unsafe byte* nt_header;
        private static unsafe byte* optional_header;
        private static uint addressOfEntryPoint;
        private static uint numberOfsections;
        private static uint imageSize;
        private static uint imageBase;
        private static uint sizeOfHeaders;
        private static uint export_tbl_rva;
        private static uint export_tbl_size;
        private static uint import_tbl_rva;
        private static uint import_tbl_size;
        private static uint basereloc_tbl_rva;
        private static uint basereloc_tbl_size;
        private static uint preferred_address;
        private static byte[] raw;
        private static ushort sizeOfOptionalHeader;
        private static IntPtr peHandle;
        private static bool is64;

    }
}
