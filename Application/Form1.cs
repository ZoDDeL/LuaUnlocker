using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Process.NET;
using Process.NET.Patterns;

namespace WindowsForms
{
    public partial class Form1 : Form
    {
        private static PatternScanner PatternScanner;
        private static ProcessSharp ProcessSharp;

        private static long LuaTaintedPtrOffset
        {
            get
            {
                var Lua_TaintedPtrOffset = GetAddressFromPattern("4C 8B 0D ?? ?? ?? ?? 45 33 C0 48 8B CE", 3, 4);
                return Lua_TaintedPtrOffset.ToInt64() - ProcessSharp.Native.MainModule.BaseAddress.ToInt64();             
            }
        }

        private static IntPtr GetAddressFromPattern(string pattern, int offset, int size)
        {
            var scanResult = PatternScanner.Find(new DwordPattern(pattern));
            return IntPtr.Add(scanResult.ReadAddress, ProcessSharp.Memory.Read<int>(scanResult.ReadAddress + offset)) + offset + size;
        }

        public Form1()
        {
            InitializeComponent();
        }

        private void InjectCode(int id, IntPtr wHandle)
        {
            byte[] asm =
            {
                0x90,                                                       //nop
                0x55,                                                       //push rbp
                0x48, 0x8B, 0xEC,                                           //mov rbp, rsp
                0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0xDE, 0xAD, 0xBE, 0xEF, //mov rcx, luaTaintedPtrOffset 
                0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,                         //mov [rcx],00000000
                0xC7, 0x41, 0x04, 0x00, 0x00, 0x00, 0x00,                   //mov [rcx+04],00000000
                0xEB, 0xF1,                                                 //jmp (to mov)
                0x48, 0x8B, 0xE5,                                           //mov rsp, rbp
                0x5D,                                                       //pop rbp
                0xC3                                                        //ret
            };

            var hAlloc = (long)VirtualAllocEx(wHandle, 0, (uint)asm.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
            WriteProcessMemory(wHandle, hAlloc, asm, asm.Length, out _);
            _ = WriteProcessMemory(wHandle, hAlloc + 0x07, BitConverter.GetBytes((long)System.Diagnostics.Process.GetProcessById(id).MainModule.BaseAddress + LuaTaintedPtrOffset), 0x08, out _);

            AllowCreateRemoteThread(true, wHandle);
            CreateRemoteThread(wHandle, IntPtr.Zero, 0, (IntPtr)hAlloc, IntPtr.Zero, 0, out _);
            Thread.Sleep(15);
            AllowCreateRemoteThread(false, wHandle);
        }

        private void AllowCreateRemoteThread(bool status, IntPtr wHandle)
        {
            byte[] Patch = {0xFF, 0xE0, 0xCC, 0xCC, 0xCC};    //JMP RAX
            byte[] Patch2 = {0x48, 0xFF, 0xC0, 0xFF, 0xE0};   //INC RAX, JMP RAX

            var CreateRemoteThreadPatchOffset = (long) GetProcAddress(GetModuleHandle("kernel32.dll"), "BaseDumpAppcompatCacheWorker") + 0x1E0;

            if (status)
                Patch = Patch2;
            _ = WriteProcessMemory(wHandle, CreateRemoteThreadPatchOffset, Patch, Patch.Length, out _);
        }

        private readonly byte[] RET = { 0xC3 };

        private void PatchAddress(IntPtr handle, string moduleName, string moduleSection, byte[] patch, int offset = 0)
        {
            var patchAddress = (long)GetProcAddress(GetModuleHandle(moduleName), moduleSection) + offset;

            var bytesRead = 0;
            var buffer = new byte[patch.Length];

            ReadProcessMemory(handle, patchAddress, buffer, patch.Length, ref bytesRead);

            WriteProcessMemory(handle, patchAddress, patch, patch.Length, out bytesRead);

            ReadProcessMemory(handle, patchAddress, buffer, patch.Length, ref bytesRead);
        }

        private void Form1_Load(object sender, EventArgs e)
        {            
            var handle = OpenProcess(0x1F0FFF, false, System.Diagnostics.Process.GetCurrentProcess().Id);
            PatchAddress(handle, "ntdll.dll", "DbgBreakPoint", RET);
            PatchAddress(handle, "ntdll.dll", "DbgUserBreakPoint", RET);               
        }

        private void btnInject_Click(object sender, EventArgs e)
        {
            try
            {
                var process = System.Diagnostics.Process.GetProcessesByName("WowB-64").FirstOrDefault();     // Wow 64 Beta 

                if (process == null)
                    process = System.Diagnostics.Process.GetProcessesByName("WowT-64").FirstOrDefault();     // Wow 64 PTR

                if (process == null)
                    process = System.Diagnostics.Process.GetProcessesByName("Wow-64").FirstOrDefault();      //  Wow 64 Live (private servers)

                if (process == null)
                    process = System.Diagnostics.Process.GetProcessesByName("WowB").FirstOrDefault();        //  Wow 64 Beta

                if (process == null)
                    process = System.Diagnostics.Process.GetProcessesByName("WowT").FirstOrDefault();        //  Wow 64 PTR

                if (process == null)
                    process = System.Diagnostics.Process.GetProcessesByName("Wow").FirstOrDefault();         // Wow 64 Live 

                if (process == null)
                    process = System.Diagnostics.Process.GetProcessesByName("WowClassic").FirstOrDefault();  // Wow 64 Classic 

                if (process == null) throw new Exception("World of warcraft is not running, nothing to unlock");

                ProcessSharp = new ProcessSharp(process, Process.NET.Memory.MemoryType.Remote);
                PatternScanner = new PatternScanner(ProcessSharp[ProcessSharp.Native.MainModule.ModuleName]);

                var wHandle = OpenProcess((int) MemoryProtection.Proc_All_Access, false, ProcessSharp.Native.Id);
                          
                InjectCode(ProcessSharp.Native.Id, wHandle);

                MessageBox.Show("Success", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failure: {ex.Message}", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        [DllImport("Kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr handle, long address, byte[] bytes, int nsize, ref int op);

        [DllImport("Kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hwind, long Address, byte[] bytes, int nsize, out int output);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(int Token, bool inheritH, int ProcID);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, long lpAddress,
            uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        private enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        private enum MemoryProtection
        {
            NoAccess = 0x0001,
            ReadOnly = 0x0002,
            ReadWrite = 0x0004,
            WriteCopy = 0x0008,
            Execute = 0x0010,
            ExecuteRead = 0x0020,
            ExecuteReadWrite = 0x0040,
            ExecuteWriteCopy = 0x0080,
            GuardModifierflag = 0x0100,
            NoCacheModifierflag = 0x0200,
            WriteCombineModifierflag = 0x0400,
            Proc_All_Access = 2035711
        }

        private void btnWebsite_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Process.Start("http://winifix.github.io/");
        }
    }
}