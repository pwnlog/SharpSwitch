using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpSwitch
{
    internal class Program
    {
        /// <summary>
        /// Strucutures Section
        /// </summary>

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        /// <summary>
        /// Flags Section
        /// </summary>

        [Flags]
        public enum CreationFlags
        {
            CREATE_SUSPENDED = 0x00000004,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
        }

        [Flags]
        public enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }

        [Flags]
        public enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        [Flags]
        public enum STARTF : uint
        {
            STARTF_USESHOWWINDOW = 0x00000001,
            STARTF_USESIZE = 0x00000002,
            STARTF_USEPOSITION = 0x00000004,
            STARTF_USECOUNTCHARS = 0x00000008,
            STARTF_USEFILLATTRIBUTE = 0x00000010,
            STARTF_RUNFULLSCREEN = 0x00000020,
            STARTF_FORCEONFEEDBACK = 0x00000040,
            STARTF_FORCEOFFFEEDBACK = 0x00000080,
            STARTF_USESTDHANDLES = 0x00000100,
            STARTF_USEHOTKEY = 0x00000200,
            STARTF_TITLEISLINKNAME = 0x00000800,
            STARTF_TITLEISAPPID = 0x00001000,
            STARTF_PREVENTPINNING = 0x00002000,
            STARTF_UNTRUSTEDSOURCE = 0x00008000,
        }

        public enum ShowState : int
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_FORCEMINIMIZE = 11,
            SW_MAX = 11
        }

        /// <summary>
        /// Constants Section
        /// </summary>

        // Standard Output, Input, Error
        const int STD_OUTPUT_HANDLE = -11;
        const int STD_INPUT_HANDLE = -10;
        const int STD_ERROR_HANDLE = -12;

        // Handle Flags
        public const uint HANDLE_FLAG_INHERIT = 0x00000001;
        public const uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;

        /// <summary>Defines the buffer size</summary>
        public const int BUFSIZE = 4096;

        /// <summary>The pipe has been ended.</summary>
        public const int ERROR_BROKEN_PIPE = 0x0000006D;

        /// <summary>
        /// DLL Imports Section
        /// </summary>

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithLogonW(
           String userName,
           String domain,
           String password,
           LogonFlags logonFlags,
           String applicationName,
           String commandLine,
           CreationFlags creationFlags,
           UInt32 environment,
           String currentDirectory,
           ref STARTUPINFO startupInfo,
           out PROCESS_INFORMATION processInformation);


        [DllImport("kernel32.dll")]
        private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode,
            uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize,
            uint nDefaultTimeOut, IntPtr lpSecurityAttributes);


        [DllImport("kernel32.dll")]
        private static extern bool PeekNamedPipe(IntPtr hNamedPipe, IntPtr lpBuffer,
            uint nBufferSize, IntPtr lpBytesRead, IntPtr lpTotalBytesAvail,
            IntPtr lpBytesLeftThisMessage);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask,
            HANDLE_FLAGS dwFlags);


        [DllImport("kernel32.dll")]
        private static extern void ExitProcess(uint uExitCode);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(byte[] hMem);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Wait);

        public const Int32 INFINITE = -1;
        public const Int32 WAIT_ABANDONED = 0x80;
        public const Int32 WAIT_OBJECT_0 = 0x00;
        public const Int32 WAIT_TIMEOUT = 0x102;
        public const Int32 WAIT_FAILED = -1;


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern Int32 GetLastError();


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);


        [DllImport("kernel32.dll")]
        static extern Boolean WriteFile(IntPtr fFile, Byte[] lpBuffer, UInt32 nNumberOfBytesToWrite,
        out UInt32 lpNumberOfBytesWritten, IntPtr lpOverlapped);

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Options.Usage();
                return;
            }

            Options options = new Options();
            if (!Parser.Default.ParseArguments(args, options))
            {
                Console.WriteLine("[-] Error: Unknown argument/s");
                return;
            }

            if (options.Help)
            {
                Options.Usage();
                return;
            }

            if (options.Username == null & options.Password == null & options.Cmd == null)
            {
                Options.Usage();
                Environment.Exit(1);
            }
            else if (options.Username == null)
            {
                Options.Usage();
                Environment.Exit(1);
            }
            else if (options.Password == null)
            {
                Options.Usage();
                Environment.Exit(1);
            }
            else if (options.Cmd == null)
            {
                Options.Usage();
                Environment.Exit(1);
            }
            else
            {
                // Verify UPN format: <username@domain.local>
                try
                {
                    WindowsIdentity wi = new WindowsIdentity(options.Username);
                    options.Domain = null;
                    Console.WriteLine("[+] Domain format detected");
                }
                catch(Exception ex)
                {
                    Console.WriteLine($"[i] Username information: {ex.Message}");
                }
                // Verify NetBIOS format: <DOMAIN\username>

                // Verify if shell is valid
                if (options.Cmd == "powershell.exe")
                {
                    SpawnConsole(options.Username, options.Domain, options.Password, options.Cmd);
                }
                else if (options.Cmd == "cmd.exe")
                {
                    SpawnConsole(options.Username, options.Domain, options.Password, options.Cmd);
                }
                else
                {
                    Console.WriteLine($"[-] Invalid shell: {options.Cmd}");
                }
            }
            static void SpawnConsole(string user, string domain, string password, string shell)
            {
                bool bSuccess;
                IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
                IntPtr hStdIn = GetStdHandle(STD_INPUT_HANDLE);
                string empty = null;
                IntPtr childInputRead = Marshal.StringToHGlobalAnsi(empty);
                IntPtr childInputWrite = Marshal.StringToHGlobalAnsi(empty);
                IntPtr childOutputRead = Marshal.StringToHGlobalAnsi(empty);
                IntPtr childOutputWrite = Marshal.StringToHGlobalAnsi(empty);
                SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
                saAttr.nLength = Marshal.SizeOf(saAttr);
                saAttr.bInheritHandle = true;
                saAttr.lpSecurityDescriptor = Marshal.StringToHGlobalAnsi(empty);

                if (!CreatePipe(out childOutputRead, out childOutputWrite, ref saAttr, 0))
                {
                    Console.WriteLine($"[-] CreatePipe error: {Marshal.GetLastWin32Error()}");
                    ExitProcess(1);
                }
                else
                {
                    Console.WriteLine("[+] Created a output pipe for child process");
                }
                if (!SetHandleInformation(childOutputRead, HANDLE_FLAGS.INHERIT, 0))
                {
                    Console.WriteLine($"[-] SetHandleInformation() error: {Marshal.GetLastWin32Error()}");
                    ExitProcess(1);
                }
                Console.WriteLine("[+] Handle for output is not inherited");
                if (!CreatePipe(out childInputRead, out childInputWrite, ref saAttr, 0))
                {
                    Console.WriteLine($"[-] CreatePipe() error: {Marshal.GetLastWin32Error()}");
                    ExitProcess(1);
                }
                else
                {
                    Console.WriteLine("[+] Created a input pipe for child process");
                }
                if (!SetHandleInformation(childInputWrite, HANDLE_FLAGS.INHERIT, 0))
                {
                    Console.WriteLine($"[-] SetHandleInformation() error: {Marshal.GetLastWin32Error()}");
                    ExitProcess(1);
                }
                else
                {
                    Console.WriteLine("[+] Handle for input is not inherited");
                }

                STARTUPINFO startupInfo = new STARTUPINFO();
                PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.dwFlags = (int)STARTF.STARTF_USESHOWWINDOW | (int)STARTF.STARTF_USESTDHANDLES;
                startupInfo.wShowWindow = (short)ShowState.SW_HIDE;
                startupInfo.hStdInput = childInputRead;
                startupInfo.hStdOutput = childOutputWrite;

                if (shell == "cmd.exe")
                {
                    if (!CreateProcessWithLogonW(user, domain, password, LogonFlags.LOGON_WITH_PROFILE, "C:\\Windows\\System32\\cmd.exe", null, CreationFlags.CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInformation))
                    {
                        Console.WriteLine($"[-] CreateProcessWithLogonW() error: {Marshal.GetLastWin32Error()}");
                        /*Console.WriteLine("[+] Attempting to logon with machine name");
                        //ExitProcess(1);
                        if (!CreateProcessWithLogonW(user, System.Environment.MachineName, password, LogonFlags.LOGON_WITH_PROFILE, "C:\\Windows\\System32\\cmd.exe", null, CreationFlags.CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInformation))
                        {
                            Console.WriteLine($"[-] CreateProcessWithLogonW() error: {Marshal.GetLastWin32Error()}");
                            ExitProcess(1);
                        }*/
                    }
                }
                else if (shell == "powershell.exe")
                {
                    if (!CreateProcessWithLogonW(user, domain, password, LogonFlags.LOGON_WITH_PROFILE, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", null, CreationFlags.CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInformation))
                    {
                        Console.WriteLine($"[-] CreateProcessWithLogonW() error: {Marshal.GetLastWin32Error()}");
                        /*Console.WriteLine("[+] Attempting to logon with machine name");
                        //ExitProcess(1);
                        if (!CreateProcessWithLogonW(user, System.Environment.MachineName, password, LogonFlags.LOGON_WITH_PROFILE, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", null, CreationFlags.CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInformation))
                        {
                            Console.WriteLine($"[-] CreateProcessWithLogonW() error: {Marshal.GetLastWin32Error()}");
                            ExitProcess(1);
                        }*/
                    }
                }
                Console.WriteLine("[+] CreateProcessWithLogonW() succeeded!");
                Console.WriteLine($"[+] Proccess spawned with PID: {processInformation.dwProcessId}");
                CloseHandle(childInputRead);
                CloseHandle(childOutputWrite);
                Console.WriteLine();

                var charBuffer = new byte[BUFSIZE];
                uint readDWORD;
                uint writeDWORD;
                bool sendEnter = true;

                while (true)
                {
                    // Automatically spawn and interact without this you would need to hit ENTER or another key to open the console
                    if (sendEnter == true && shell == "cmd.exe")
                    {
                        ReadFile(childOutputRead, charBuffer, BUFSIZE, out readDWORD, Marshal.StringToHGlobalAnsi(empty));
                        sendEnter = false;
                        WriteFile(hStdOut, charBuffer, readDWORD, out writeDWORD, Marshal.StringToHGlobalAnsi(empty));
                    }
                    else if (sendEnter == true && shell == "powershell.exe")
                    {
                        ReadFile(childOutputRead, charBuffer, BUFSIZE, out readDWORD, Marshal.StringToHGlobalAnsi(empty));
                        WriteFile(hStdOut, charBuffer, readDWORD, out writeDWORD, Marshal.StringToHGlobalAnsi(empty));
                        ReadFile(childOutputRead, charBuffer, BUFSIZE, out readDWORD, Marshal.StringToHGlobalAnsi(empty));
                        WriteFile(hStdOut, charBuffer, readDWORD, out writeDWORD, Marshal.StringToHGlobalAnsi(empty));
                        sendEnter = false;
                    }
                    bSuccess = ReadFile(childOutputRead, charBuffer, BUFSIZE, out readDWORD, Marshal.StringToHGlobalAnsi(empty));
                    if (GetLastError() == ERROR_BROKEN_PIPE && bSuccess == false)
                    {
                        break;
                    }
                    bSuccess = WriteFile(hStdOut, charBuffer, readDWORD, out writeDWORD, Marshal.StringToHGlobalAnsi(empty));

                    while (true)
                    {
                        int bytesAvailable = 0;
                        if (!PeekNamedPipe(childOutputRead, Marshal.StringToHGlobalAnsi(empty), BUFSIZE, Marshal.StringToHGlobalAnsi(empty), (IntPtr)bytesAvailable, Marshal.StringToHGlobalAnsi(empty)))
                        {
                            Console.WriteLine($"\nBye!: {Marshal.GetLastWin32Error()}");
                            WaitForSingleObject(processInformation.hProcess, INFINITE);
                            LocalFree(charBuffer);
                            CloseHandle(processInformation.hProcess);
                            CloseHandle(processInformation.hThread);
                            ExitProcess(1);
                        }
                        if (bytesAvailable != 0)
                        {

                            bSuccess = ReadFile(childOutputRead, charBuffer, BUFSIZE, out readDWORD, Marshal.StringToHGlobalAnsi(empty));
                            if (Marshal.GetLastWin32Error() == ERROR_BROKEN_PIPE && bSuccess == false)
                            {
                                break;
                            }
                            bSuccess = WriteFile(hStdOut, charBuffer, readDWORD, out writeDWORD, Marshal.StringToHGlobalAnsi(empty));
                        }
                        else
                        {
                            break;
                        }
                    }
                    bSuccess = ReadFile(hStdIn, charBuffer, BUFSIZE, out readDWORD, Marshal.StringToHGlobalAnsi(empty));
                    bSuccess = WriteFile(childInputWrite, charBuffer, readDWORD, out writeDWORD, Marshal.StringToHGlobalAnsi(empty));
                    Thread.Sleep(1000);
                }
            }
        }
    }
}
