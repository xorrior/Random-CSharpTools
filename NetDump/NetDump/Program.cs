using NDesk.Options;
using System;
using System.Text;
using System.IO;
using System.Collections.Generic;
using Microsoft.Diagnostics.Runtime;
using System.Text.RegularExpressions;

/// <summary>
/// Author: Chris Ross @xorrior
/// License: BSD3
/// Purpose: Dump objects and reference objects from a managed process
/// </summary>

namespace NetDump
{
    class Program
    {
        public static void Main(string[] args)
        {
            OptionSet opts = new OptionSet()
            {
                {"r|refObjects", "Dump reference objects and their values, if possible.", v => referenceObjects = v != null },
                {"f|fields", "Show the value of a field, if the field HasSimpleValue property is true", v => showFields = v != null },
                { "sf|staticFields", "Show the values of a static field, if the field HasSimpleValue is true", v => showstaticFields = v != null },
                {"m|methods", "Enumerate all of the available methods for each type", v => showMethods = v != null },
                {"p=|pid=","ProcessId of the managed process", (int v) =>  targetPID = v},
                {"h|help", "Show the help menu", v => help = v != null }
            };

            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            if (help == true || targetPID == 0)
            {
                Console.WriteLine("Usage: NetDump.exe [options]");
                Console.WriteLine("Copyright (c) Chris Ross 2017. Licensed under BSD-3 Clause");
                Console.WriteLine("Options:\r\n");
                opts.WriteOptionDescriptions(Console.Error);
                System.Environment.Exit(0);
            }

            KeyValuePair<bool, string> result = Enumerate();

            if (result.Key)
            {
                Console.WriteLine(result.Value.ToString());

                Console.WriteLine("[+] Complete");
            }
            else
            {
                Console.WriteLine(result.Value.ToString());
                System.Environment.Exit(0);
            }


            if (resultOutput.Length != 0)
                Console.WriteLine(resultOutput.ToString());
            else
                Console.WriteLine("[+] No results");
        }

        private static KeyValuePair<bool, string> Enumerate()
        {
            //Attach to target process
            DataTarget dt = null;
            try
            {
                dt = DataTarget.AttachToProcess(targetPID, 10000, AttachFlag.NonInvasive);
            }
            catch (Exception e)
            {
                return new KeyValuePair<bool, string>(false, e.ToString());
            }

            //If no ClrVersions, return
            if (dt.ClrVersions.Count == 0)
                return new KeyValuePair<bool, string>(false, "[!] No Clr Versions detected");

#if DEBUG
            foreach (var ver in dt.ClrVersions)
            {
                Console.WriteLine("Clr Runtime Version Found: " + ver.Version.ToString());
            }
#endif

            ClrInfo Version = dt.ClrVersions[0];


            try
            {
                cRun = Version.CreateRuntime();
#if DEBUG
                Console.WriteLine("[+] Created Runtime");
#endif
            }
            catch (Exception e)
            {
#if DEBUG 
                Console.WriteLine("[!] Failed to create runtime");
#endif
                return new KeyValuePair<bool, string>(false, e.ToString());
            }


            ClrHeap Heap = cRun.GetHeap();

            //if we can't walk the heap, return
            if (!Heap.CanWalkHeap)
                return new KeyValuePair<bool, string>(false, "[!] Unable to walk the heap");

            Console.WriteLine("[+] Walking the heap....");
            string m = WildCardToRegWithQM("System.*");
            string m1 = WildCardToRegWithQM("_*");
            string m2 = WildCardToRegWithQM("Microsoft.*");
            foreach (ulong obj in Heap.EnumerateObjectAddresses())
            {
                //Grab each object, check if it has a simple value, if so, display it
                ClrType type = Heap.GetObjectType(obj);

                if (type == null || Regex.IsMatch(type.Name, m) || Regex.IsMatch(type.Name, m1) || Regex.IsMatch(type.Name, m2) || type.Name == "Free")
                    continue;

                if (!type.IsPrimitive)
                {
#if DEBUG 
                    Console.WriteLine("[+] Enumerating type: " + type.Name);
#endif
                    //if the type has a simple value, add the type and its value to the results
                    resultOutput.Append("\r\nType: " + type.Name + "\r\n\r\n");
                    //Enumerate all of the instance fields for the given type
                    if (showFields)
                    {
                        if (type.Fields != null)
                            GetInstanceFields(type.Fields, obj);
                    }


                    if (showstaticFields)
                    {
                        if (type.StaticFields != null)
                            GetStaticFields(type.StaticFields, cRun.AppDomains[0]);
                    }

                    if (showMethods)
                    {
                        if (type.Methods != null)
                            GetMethods(type.Methods);
                    }

                    if (referenceObjects)
                    {
                        resultOutput.Append("\r\nReferencedTypes\r\n\r\n");
                        List<ulong> referencedObjects = ClrMDHelper.GetReferencedObjects(Heap, obj);
                        foreach (ulong refObj in referencedObjects)
                        {
                            ClrType refObjType = Heap.GetObjectType(refObj);
                            if (refObjType == null || Regex.IsMatch(refObjType.Name, m) || Regex.IsMatch(refObjType.Name, m1) || Regex.IsMatch(refObjType.Name, m2) || refObjType.Name == "Free")
                                continue;

                            if (showFields)
                            {
                                if (refObjType.Fields != null)
                                    GetInstanceFields(refObjType.Fields, obj);
                            }

                            if (showstaticFields)
                            {
                                if (refObjType.StaticFields != null)
                                    GetStaticFields(refObjType.StaticFields, cRun.AppDomains[0]);
                            }

                            if (showMethods)
                            {
                                if (refObjType.Methods != null)
                                    GetMethods(refObjType.Methods);
                            }
                        }
                    }
                }

            }

            return new KeyValuePair<bool, string>(true, "[+] Successfully walked the heap.");
        }

        private static void GetInstanceFields(IList<ClrInstanceField> fields, ulong obj)
        {
            object fieldValue;
#if DEBUG 
            Console.WriteLine("[+] Grabbing instance fields");
#endif
            resultOutput.Append("\r\nInstanceFields\r\n\r\n");
            foreach (ClrInstanceField var in fields)
            {
                if (var.HasSimpleValue && var.ElementType == ClrElementType.String)
                {
                    try
                    {
                        fieldValue = var.GetValue(obj);
                    }
                    catch (Exception)
                    {
                        fieldValue = "";
                    }
                    object[] args = new object[] { var.Name, var.HasSimpleValue.ToString(), fieldValue };
                    resultOutput.AppendLine(string.Format("{0,-35} {1,-10} {2,-10}", args));
                }
                else if (var.HasSimpleValue)
                {
                    //treat everything else as a pointer
                    try
                    {
                        fieldValue = var.GetValue(obj);
                    }
                    catch (Exception)
                    {
                        fieldValue = "";
                    }
                    object[] args = new object[] { var.Name, var.HasSimpleValue.ToString(), fieldValue.ToString() };
                    resultOutput.AppendLine(string.Format("{0,-35} {1,-10} {2,-10}", args));
                }
            }
        }

        private static void GetStaticFields(IList<ClrStaticField> fields, ClrAppDomain app)
        {
            object fieldValue;
#if DEBUG
            Console.WriteLine("[+] Grabbing static fields");
#endif
            resultOutput.Append("\r\nStaticFields\r\n\r\n");
            foreach (ClrStaticField var in fields)
            {
                if (var.HasSimpleValue && var.ElementType == ClrElementType.String)
                {

                    try
                    {
                        fieldValue = var.GetValue(app);
                    }
                    catch (Exception)
                    {
                        fieldValue = "";
                    }
                    object[] args = new object[] { var.Name, var.HasSimpleValue.ToString(), fieldValue };
                    resultOutput.AppendLine(string.Format("{0,-35} {1,-10} {2,-10}", args));
                }
                else if (var.HasSimpleValue)
                {
                    //treat everything else as a pointer
                    try
                    {
                        fieldValue = var.GetValue(app);
                    }
                    catch (Exception)
                    {
                        fieldValue = "";
                    }
                    
                    object[] args = new object[] { var.Name, var.HasSimpleValue.ToString(), fieldValue.ToString() };
                    resultOutput.AppendLine(string.Format("{0,-35} {1,-10} {2,-10}", args));
                }
            }
        }

        private static void GetMethods(IList<ClrMethod> methods)
        {
#if DEBUG
            Console.WriteLine("[+] Grabbing methods");
#endif
            resultOutput.Append("\r\nMethods\r\n\r\n");
            foreach (ClrMethod m in methods)
            {
                if (!m.IsConstructor || !m.IsClassConstructor || !m.IsPInvoke || !m.IsRTSpecialName || !m.IsSpecialName)
                {
                    object[] args = new object[] { m.Name, m.NativeCode.ToString("X8"), m.GetFullSignature() };
                    resultOutput.AppendLine(string.Format("{0,-35} {1,-10} {2,-10}", args));
                }
            }
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



        private static bool help = false;
        private static bool showFields = false;
        private static bool showstaticFields = false;
        private static bool showMethods = false;
        private static bool referenceObjects = false;
        private static ClrRuntime cRun = null;
        private static StringBuilder resultOutput = new StringBuilder();
        private static int targetPID = 0;
    }
}
