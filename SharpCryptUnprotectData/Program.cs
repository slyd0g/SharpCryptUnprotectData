using System;
using System.Runtime.InteropServices;
using System.Linq;
using System.IO;

namespace SharpCryptUnprotectData
{
    class Program
    {
        // Source for structures and P/Invoke: https://github.com/vincepare/DPAPIbridge/blob/master/src/DPAPI.cs
        // Wrapper for DPAPI CryptUnprotectData function.
        [DllImport("crypt32.dll",
                    SetLastError = true,
                    CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern
        bool CryptUnprotectData(ref DATA_BLOB pCipherText,
                                string pszDescription,
                                DATA_BLOB pEntropy,
                                IntPtr pReserved,
                                CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                int dwFlags,
                                ref DATA_BLOB pPlainText);

        // BLOB structure used to pass data to DPAPI functions.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        // Prompt structure to be used for required parameters.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        static void Help()
        {
            Console.WriteLine("Help: SharpCryptUnprotectData.exe -h/-help");
            Console.WriteLine("Usage: SharpCryptUnprotectData.exe -data <B64_encoded_DPAPI_encrypted_blob>");
            Console.WriteLine("       SharpCryptUnprotectData.exe -outfile slyd0g.txt -data <B64_encoded_DPAPI_encrypted_blob>");
        }

        static void Main(string[] args)
        {
            // Print help if no args
            if (args == null || args.Length == 0 || (args[0] == "-h") || (args[0] == "-help"))
            {
                Help();
                System.Environment.Exit(0);
            }

            // Check for -outfile
            if (args.Contains("-outfile")) {
                int outfileIndex = Array.IndexOf(args, "-outfile") + 1;
                string outfileName = args[outfileIndex];

                // https://stackoverflow.com/questions/4470700/how-to-save-console-writeline-output-to-text-file/4470751
                FileStream filestream = new FileStream(outfileName, FileMode.Create);
                var streamwriter = new StreamWriter(filestream);
                streamwriter.AutoFlush = true;
                Console.SetOut(streamwriter);
                Console.SetError(streamwriter);
            }

            // Read b64 string from commandline
            byte[] b64Input = null;
            if (args.Contains("-data"))
            {
                int dataIndex = Array.IndexOf(args, "-data") + 1;
                b64Input = Convert.FromBase64String(args[dataIndex]);
            }
            else
            {
                Help();
                System.Environment.Exit(0);
            }

            // Convert b64 string into DATA_BLOB struct
            DATA_BLOB dataIn;
            GCHandle pinnedArray = GCHandle.Alloc(b64Input, GCHandleType.Pinned);
            dataIn.pbData = pinnedArray.AddrOfPinnedObject();
            dataIn.cbData = b64Input.Length;
            Console.WriteLine("[+] Encrypted Blob Length: {0}", dataIn.cbData);

            // Prepare other paramters for CryptUnprotectData() call
            DATA_BLOB dataOut = new DATA_BLOB();
            DATA_BLOB optionalEntropy = new DATA_BLOB();
            CRYPTPROTECT_PROMPTSTRUCT promptStruct = new CRYPTPROTECT_PROMPTSTRUCT();

            // Call CryptUnprotectData()
            bool success = CryptUnprotectData(ref dataIn, null, optionalEntropy, IntPtr.Zero, promptStruct, 0, ref dataOut);
            if (success)
            {
                byte[] decryptedBytes = new byte[dataOut.cbData];
                Marshal.Copy(dataOut.pbData, decryptedBytes, 0, dataOut.cbData);
                var b64Output = Convert.ToBase64String(decryptedBytes);

                Console.WriteLine("[+] CryptUnprotectData() success!");
                Console.WriteLine("     |-> Decrypted Blob Length: {0}", dataOut.cbData);
                Console.WriteLine("     |-> Base64 Encoded Blob: {0}", b64Output);
            }
            else
            {
                Console.WriteLine("[-] CryptUnprotectData() failed with error: {0}", Marshal.GetLastWin32Error());
            }
            pinnedArray.Free();
        }
    }
}