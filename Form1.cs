using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Memory;

namespace FPS_Bypass
{
    public partial class Form1 : Form
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void SetLastError(uint dwErrorCode);
        [DllImport("kernel32.dll")]
        public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll")]
        protected static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        protected static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr processHandle,
         [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
        [DllImport("kernel32.dll", EntryPoint = "GetProcessId", CharSet = CharSet.Auto)]
        static extern int GetProcessId(IntPtr handle);
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static string GetSystemMessage(uint errorCode)
        {
            var exception = new System.ComponentModel.Win32Exception((int)errorCode);
            return exception.Message;
        }
        [StructLayout(LayoutKind.Sequential)]
        protected struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        private enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }
        private enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }
        private enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }
        byte[] current_aob = null;
        string mask = "";
        IntPtr handle = IntPtr.Zero;
        int pid = 0;
        bool is_valid_hex_array(string text)
        {
            var regex = new Regex(@"^([a-fA-F0-9]{2}?(.*\?)?\s?)+$");
            var match = regex.Match(text);
            return (match.Success);
        }
        bool is_valid_pattern_mask(string text)
        {
            var regex = new Regex(@"^([\\*][x][a-fA-F0-9]{2})+$");
            var match = regex.Match(text);
            return (match.Success);
        }
        bool is_valid_mask(string text)
        {
            var regex = new Regex(@"^([xX]?(.*\?)?)+$");
            var match = regex.Match(text);
            return (match.Success);
        }
        int str_array_to_aob(string inputed_str)
        {
            var trated_str = inputed_str.Replace("  ", "");
            trated_str = (trated_str[0] == ' ') ? trated_str.Substring(1, trated_str.Length - 1) : trated_str;
            trated_str = (trated_str.Substring(trated_str.Length - 1, 1) == " ") ? trated_str.Substring(0, trated_str.Length - 1) : trated_str;

            if (!is_valid_hex_array(trated_str))
            {
                MessageBox.Show("not valid hex array {x1F0}", "by dotNetMemoryScan");
                return 0;
            }

            mask = "";
            var part_hex = inputed_str.Split(' ');
            current_aob = new byte[part_hex.Count()];
            for (var i = 0; i < part_hex.Count(); ++i)
            {
                if (part_hex[i].Contains("?"))
                {
                    current_aob[i] = 0xCC;
                    mask += "?";
                }
                else
                {
                    current_aob[i] = Convert.ToByte(part_hex[i], 16);
                    mask += "x";
                }
            }
            return part_hex.Count();
        }
        int pattern_to_aob(string inputed_str, string i_mask)
        {
            if (!is_valid_mask(i_mask))
                return 0;
            var trated_str = inputed_str.Replace(" ", "");
            if (!is_valid_pattern_mask(trated_str))
            {
                MessageBox.Show("not valid pattern {x1F0}", "by dotNetMemoryScan");
                return 0;
            }

            var part_hex = inputed_str.Split(new[] { @"\x" }, StringSplitOptions.None);
            if ((part_hex.Count() - 1) != i_mask.Length)
                return 0;
            mask = i_mask;
            current_aob = new byte[part_hex.Count() - 1];
            for (var i = 1; i < part_hex.Count(); ++i)
            {
                var l = i - 1;
                if (i_mask[l] == '?')
                    current_aob[l] = 0xCC;
                else
                    current_aob[l] = Convert.ToByte(part_hex[i], 16);
            }
            return part_hex.Count();
        }

        int pattern_to_aob(string inputed_str)
        {
            var trated_str = inputed_str.Replace(" ", "");
            if (!is_valid_pattern_mask(trated_str))
            {
                MessageBox.Show("not valid pattern {x1F1}", "by dotNetMemoryScan");
                return 0;
            }
            var part_hex = inputed_str.Split(new[] { @"\x" }, StringSplitOptions.None);
            current_aob = new byte[part_hex.Count() - 1];
            for (var i = 1; i < part_hex.Count(); ++i)
                current_aob[i - 1] = Convert.ToByte(part_hex[i], 16);
            return part_hex.Count();
        }
        public static bool IsAdministrator()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))
                      .IsInRole(WindowsBuiltInRole.Administrator);
        }
        IntPtr get_handle(Process p)
        {
            if (p == null)
                return IntPtr.Zero;
            try
            { return p.Handle; }
            catch (Exception ex)
            {
                if (!IsAdministrator())
                    MessageBox.Show("Run the program as an administrator.", "by dotNetMemoryScan");
                else
                    MessageBox.Show("error: " + ex.Message);
            }
            return IntPtr.Zero;
        }

        public IntPtr scan_all(IntPtr handle, string pattern)
        {
            if (str_array_to_aob(pattern) == 0)
                return IntPtr.Zero;
            this.handle = handle;
            this.pid = GetProcessId(this.handle);
            return scan_all_regions();
        }
        public IntPtr scan_all(Process p, string pattern)
        {
            var by_handle = get_handle(p);
            if (by_handle != IntPtr.Zero)
                return scan_all(by_handle, pattern);
            return IntPtr.Zero;
        }
        public IntPtr scan_all(string p_name, string pattern)
        {
            var by_handle = get_handle(GetPID(p_name.Replace(".exe", "")));
            if (by_handle != IntPtr.Zero)
                return scan_all(by_handle, pattern);
            return IntPtr.Zero;
        }
        public IntPtr scan_all(int pid, string pattern)
        {
            var by_handle = get_handle(Process.GetProcessById(pid));
            if (by_handle != IntPtr.Zero)
                return scan_all(by_handle, pattern);
            return IntPtr.Zero;
        }

        public IntPtr scan_all(IntPtr handle, string pattern, string mask)
        {
            if (pattern_to_aob(pattern, mask) == 0)
                return IntPtr.Zero;
            this.handle = handle;
            return scan_all_regions();
        }
        public IntPtr scan_all(Process p, string pattern, string mask)
        {
            var by_handle = get_handle(p);
            if (by_handle != IntPtr.Zero)
                return scan_all(by_handle, pattern, mask);
            return IntPtr.Zero;
        }
        public IntPtr scan_all(string p_name, string pattern, string mask)
        {
            var by_handle = get_handle(GetPID(p_name.Replace(".exe", "")));
            if (by_handle != IntPtr.Zero)
                return scan_all(by_handle, pattern, mask);
            return IntPtr.Zero;
        }
        public IntPtr scan_all(int pid, string pattern, string mask)
        {
            var by_handle = get_handle(Process.GetProcessById(pid));
            if (by_handle != IntPtr.Zero)
                return scan_all(by_handle, pattern, mask);
            return IntPtr.Zero;
        }

        public IntPtr scan_module(Process p, string module_name, string pattern)
        {
            this.handle = get_handle(p);
            if (this.handle == IntPtr.Zero)
                return IntPtr.Zero;
            if (str_array_to_aob(pattern) == 0)
                return IntPtr.Zero;
            return module_region(p, module_name);
        }
        public IntPtr scan_module(int pid, string module_name, string pattern)
        {
            var p = Process.GetProcessById(pid);
            if (p != null)
                return scan_module(p, module_name, pattern);
            return IntPtr.Zero;
        }
        public IntPtr scan_module(string p_name, string module_name, string pattern)
        {
            var p = GetPID(p_name.Replace(".exe", ""));
            if (p != null)
                return scan_module(p, module_name, pattern);
            return IntPtr.Zero;
        }
        public IntPtr scan_module(IntPtr handle, string module_name, string pattern)
        {
            int pid = GetProcessId(handle);
            if (pid == 0)
                return IntPtr.Zero;
            return scan_module(pid, module_name, pattern);
        }
        public IntPtr scan_module(Process p, string module_name, string pattern, string mask)
        {
            this.handle = get_handle(p);
            if (this.handle == IntPtr.Zero)
                return IntPtr.Zero;
            if (pattern_to_aob(pattern, mask) == 0)
                return IntPtr.Zero;
            return module_region(p, module_name);
        }
        public IntPtr scan_module(int pid, string module_name, string pattern, string mask)
        {
            var p = Process.GetProcessById(pid);
            if (p != null)
                return scan_module(p, module_name, pattern, mask);
            return IntPtr.Zero;
        }
        public IntPtr scan_module(string p_name, string module_name, string pattern, string mask)
        {
            var p = GetPID(p_name.Replace(".exe", ""));
            if (p != null)
                return scan_module(p, module_name, pattern, mask);
            return IntPtr.Zero;
        }
        public IntPtr scan_module(IntPtr handle, string module_name, string pattern, string mask)
        {
            int pid = GetProcessId(handle);
            if (pid == 0)
                return IntPtr.Zero;
            return scan_module(pid, module_name, pattern, mask);
        }

        protected bool map_process_memory(IntPtr pHandle, List<MEMORY_BASIC_INFORMATION> mapped_memory)
        {
            IntPtr address = new IntPtr();
            MEMORY_BASIC_INFORMATION MBI = new MEMORY_BASIC_INFORMATION();

            var found = VirtualQueryEx(pHandle, address, out MBI, (uint)Marshal.SizeOf(MBI));
            while (found != 0)
            {
                if ((MBI.State & (uint)StateEnum.MEM_COMMIT) != 0 && (MBI.Protect & (uint)AllocationProtectEnum.PAGE_GUARD) != (uint)AllocationProtectEnum.PAGE_GUARD)
                    mapped_memory.Add(MBI);
                address = new IntPtr(MBI.BaseAddress.ToInt64() + (uint)MBI.RegionSize);
            }
            return (mapped_memory.Count() > 0);
        }
        int is_x64_process(IntPtr by_handle)
        {
            var is_64 = false;
            if (!IsWow64Process(by_handle, out is_64))
                return -1;
            return Convert.ToInt32(!is_64);
        }
        int search_pattern(byte[] buffer, int init_index)
        {
            for (var i = init_index; i < buffer.Count(); ++i)
            {
                for (var x = 0; x < current_aob.Count(); x++)
                {
                    if (current_aob[x] != buffer[i + x] && mask[x] != '?')
                        goto end;
                }
                return i;
            end:;
            }
            return 0;
        }
        IntPtr module_region(Process p, string module_str)
        {
            if (is_x64_process(Process.GetCurrentProcess().Handle) != is_x64_process(this.handle))
            {
                MessageBox.Show("Problems with retaining information or architectural incompatibility with the target process.", "by dotNetMemoryScan");
                return IntPtr.Zero;
            }
            var mod = find_module(p, module_str);
            if (mod == null)
                return IntPtr.Zero;
            byte[] buffer = new byte[mod.ModuleMemorySize];
            uint NumberOfBytesRead;
            if (ReadProcessMemory(handle, mod.BaseAddress, buffer, (uint)mod.ModuleMemorySize, out NumberOfBytesRead) && NumberOfBytesRead > 0)
            {
                var ret = search_pattern(buffer, 0);
                if (ret != 0)
                    return (IntPtr)(mod.BaseAddress.ToInt64() + ret);
            }

            return IntPtr.Zero;
        }
        IntPtr scan_all_regions()
        {
            if (is_x64_process(Process.GetCurrentProcess().Handle) != is_x64_process(this.handle))
            {
                MessageBox.Show("Problems with retaining information or architectural incompatibility with the target process.", "by dotNetMemoryScan");
                return IntPtr.Zero;
            }
            var mapped_memory = new List<MEMORY_BASIC_INFORMATION>();
            if (!map_process_memory(handle, mapped_memory))
                return IntPtr.Zero;

            for (int i = 0; i < mapped_memory.Count(); i++)
            {
                byte[] buffer = new byte[(uint)mapped_memory[i].RegionSize];
                uint NumberOfBytesRead;
                if (ReadProcessMemory(handle, mapped_memory[i].BaseAddress, buffer, (uint)mapped_memory[i].RegionSize, out NumberOfBytesRead) && NumberOfBytesRead > 0)
                {
                    var ret = search_pattern(buffer, 0);
                    if (ret != 0)
                        return (IntPtr)(mapped_memory[i].BaseAddress.ToInt64() + ret);
                }
                var error_code = GetLastError();
                if (error_code == 6)//sometimes .net closes the handle.
                {
                    var p = Process.GetProcessById(pid);
                    if (p != null)
                        this.handle = p.Handle;
                }
            }
            return IntPtr.Zero;
        }
        public Process GetPID(string ProcessName)
        {
            try
            { return Process.GetProcessesByName(ProcessName)[0]; }
            catch { }
            return null;
        }
        bool write_mem(IntPtr address, string pattern)
        {
            var size = 0;
            if (pattern.Contains(@"\x"))
                size = pattern_to_aob(pattern);
            else
                size = str_array_to_aob(pattern);
            if (size == 0)
                return false;
            uint old_p = 0;
            if (!VirtualProtectEx(handle, address, (UIntPtr)size, (uint)AllocationProtectEnum.PAGE_EXECUTE_READWRITE, out old_p))
                return false;
            var ret = WriteProcessMemory(handle, address, current_aob, (uint)size, 0);
            VirtualProtectEx(handle, address, (UIntPtr)size, old_p, out old_p);
            return ret;
        }
        public bool write_mem(IntPtr handle, IntPtr address, string pattern)
        {
            if (address == null)
                return false;
            this.handle = handle;
            return write_mem(address, pattern);
        }
        public bool write_mem(Process p, IntPtr address, string pattern)
        {
            var by_handle = get_handle(p);
            if (by_handle == IntPtr.Zero)
                return false;
            return write_mem(by_handle, address, pattern);
        }
        public bool write_mem(string p_name, IntPtr address, string pattern)
        {
            var by_handle = get_handle(GetPID(p_name.Replace(".exe", "")));
            if (by_handle == IntPtr.Zero)
                return false;
            return write_mem(by_handle, address, pattern);
        }
        public bool write_mem(int pid, IntPtr address, string pattern)
        {
            var by_handle = get_handle(Process.GetProcessById(pid));
            if (by_handle == IntPtr.Zero)
                return false;
            return write_mem(by_handle, address, pattern);

        }
        public ProcessModule find_module(Process p, string module_str)
        {
            foreach (ProcessModule modu in p.Modules)
            {
                if (modu.FileName.ToLower().Contains(module_str.ToLower()))
                    return modu;
            }
            return null;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
           UInt32 DesiredAccess, out IntPtr TokenHandle);

        private static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private static uint STANDARD_RIGHTS_READ = 0x00020000;
        private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private static uint TOKEN_DUPLICATE = 0x0002;
        private static uint TOKEN_IMPERSONATE = 0x0004;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_QUERY_SOURCE = 0x0010;
        private static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private static uint TOKEN_ADJUST_GROUPS = 0x0040;
        private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        private static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
            out LUID lpLuid);

        public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        public const string SE_AUDIT_NAME = "SeAuditPrivilege";

        public const string SE_BACKUP_NAME = "SeBackupPrivilege";

        public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";

        public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";

        public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";

        public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";

        public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";

        public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";

        public const string SE_DEBUG_NAME = "SeDebugPrivilege";

        public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";

        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";

        public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";

        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";

        public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";

        public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";

        public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";

        public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";

        public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";

        public const string SE_RELABEL_NAME = "SeRelabelPrivilege";

        public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";

        public const string SE_RESTORE_NAME = "SeRestorePrivilege";

        public const string SE_SECURITY_NAME = "SeSecurityPrivilege";

        public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";

        public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";

        public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";

        public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";

        public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";

        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

        public const string SE_TCB_NAME = "SeTcbPrivilege";

        public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";

        public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";

        public const string SE_UNDOCK_NAME = "SeUndockPrivilege";

        public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        // Use this signature if you do not want the previous state
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 Zero,
           IntPtr Null1,
           IntPtr Null2);

        public static void GoDebugPriv()
        {
            IntPtr hToken;
            LUID luidSEDebugNameValue;
            TOKEN_PRIVILEGES tkpPrivileges;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                return;
            }
            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luidSEDebugNameValue))
            {
                CloseHandle(hToken);
                return;
            }
            tkpPrivileges.PrivilegeCount = 1;
            tkpPrivileges.Luid = luidSEDebugNameValue;
            tkpPrivileges.Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(hToken);
        }
        public Mem m = new Mem();
        public Form1()
        {
            GoDebugPriv();
            InitializeComponent();
        }
        private void Form1_Load(object sender, EventArgs e)
        {
            textBox1.KeyPress += new System.Windows.Forms.KeyPressEventHandler(textBox1_KeyPress);
        }

        private static string CalculateHexForFps(double fps)
        {
            double reciprocal = 1.0 / fps;
            ulong hexValue = BitConverter.ToUInt64(BitConverter.GetBytes(reciprocal), 0);
            string hexString = hexValue.ToString("X16");
            char[] reversedHex = new char[16];
            for (int i = 0; i < 16; i += 2)
            {
                reversedHex[i] = hexString[14 - i];
                reversedHex[i + 1] = hexString[15 - i];
            }

            return new string(reversedHex);
        }

        public bool patched = false;
        public string savepatch;
        private void button1_Click(object sender, EventArgs e)
        {
            var test1 = IntPtr.Zero;

            string module = "Battles-Win.exe";
            string original = "11 11 11 11 11 11 91 3F";

            CheckForIllegalCrossThreadCalls = false;

            int iProcID = m.GetProcIdFromName(module);

            if (iProcID > 0)
            {
                m.OpenProcess(iProcID);
                if (string.IsNullOrEmpty(textBox1.Text))
                {
                    MessageBox.Show("You cannot do that.");
                }
                else
                {
                    if (int.TryParse(textBox1.Text, out int result))
                    {
                        if (result < 60)
                        {
                            MessageBox.Show("Why would you want to do that?");
                        }
                        else if(result > 600)
                        {
                            MessageBox.Show("Why would you want to do that?");
                        }

                        else
                        {
                            double value = Convert.ToDouble(textBox1.Text);

                            string final = CalculateHexForFps(value);

                            if (patched == false)
                            {
                                test1 = scan_module(module, module, original);

                                string output = InsertSpacesEveryTwoCharacters(final);

                                write_mem(module, test1, output);

                                savepatch = output;

                                patched = true;
                            }
                            else
                            {
                                test1 = scan_module(module, module, savepatch);

                                string output = InsertSpacesEveryTwoCharacters(final);

                                write_mem(module, test1, output);

                                savepatch = output;

                                patched = true;
                            }
                        }

                    }
                }
            }
            else
            {
                MessageBox.Show("Open Battles first.");
            }
        }

        //Before you ask, the AOB scanner would cry about the input not being formatted properly
        public static string InsertSpacesEveryTwoCharacters(string input)
        {
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < input.Length; i++)
            {
                result.Append(input[i]);

                if ((i + 1) % 2 == 0 && i != input.Length - 1)
                {
                    result.Append(' ');
                }
            }
            return result.ToString();
        }

        private void textBox1_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (!char.IsDigit(e.KeyChar) && e.KeyChar != (char)Keys.Back && e.KeyChar != '.')
            {
                e.Handled = true;
            }
            else
            {
                if (e.KeyChar == '.' && ((TextBox)sender).Text.Contains("."))
                {
                    e.Handled = true;
                }
            }
        }
    }
}
