using System;
using System.ComponentModel;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ysonet.Tests
{
    /// <summary>
    /// A job object owned by the TEST RUNNER that stops an unhandled exception anywhere in
    /// the automated process tree from putting Windows Error Reporting UI on screen.
    ///
    /// Why a job and not a SetErrorMode call: the crash does not happen here. It happens in
    /// a deserialized payload, in a ysonet.exe child the harness started, or in a grandchild
    /// that child spawned. JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION applies
    /// SEM_NOGPFAULTERRORBOX to every process associated with the job, and a normal child
    /// inherits its parent's job, so one job at the top covers the whole tree. Calling
    /// SetErrorMode in each known crasher would miss the next one, and calling it inside
    /// ysonet.exe would change what a maintainer sees from a hand-run "ysonet.exe -t", which
    /// this work must not do.
    ///
    /// What it deliberately does NOT do: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is not set. The
    /// point is to suppress crash UI, not to redefine child lifetime or to hide a hang. Note
    /// that without that flag, closing the last job handle does not kill the members either,
    /// so do not describe the job as dying with the runner.
    ///
    /// Every failure here is non-fatal. A host policy or an outer job can refuse creation or
    /// assignment; that prints one line and the run continues uncontained.
    /// </summary>
    internal sealed class WerContainment : IDisposable
    {
        /// <summary>True when this process is a member of a test-owned job with the flag set.</summary>
        public bool Active { get; private set; }

        /// <summary>The value shown after "WER containment:" in the run header and in the status file.</summary>
        public string Description { get; private set; }

        /// <summary>Kernel object name, so a child can prove membership in THIS job, not in any job.</summary>
        public string JobName { get; private set; }

        private SafeJobHandle _job;

        private WerContainment() { }

        /// <summary>Off, or unavailable: nothing was created, nothing needs disposing.</summary>
        private static WerContainment Inactive(string description)
        {
            return new WerContainment { Active = false, Description = description };
        }

        public static WerContainment Apply(WerContainmentMode mode)
        {
            return Apply(mode, RealJobApi.Instance, System.Diagnostics.Process.GetCurrentProcess().Id);
        }

        /// <summary>
        /// The testable form. Every native step goes through <paramref name="api"/> so
        /// WerContainmentFailureFallsBack can force each seam to fail and prove the helper
        /// disposes what it made, describes itself honestly, and never throws.
        /// </summary>
        public static WerContainment Apply(WerContainmentMode mode, IJobNativeApi api, int pid)
        {
            if (mode == WerContainmentMode.Off)
                return Inactive("off");

            string name = "ysonet-tests-wer-" + pid + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            SafeJobHandle job = null;
            try
            {
                int error;
                job = api.CreateJob(name, out error);
                if (job == null || job.IsInvalid)
                    return Unavailable(ref job, "CreateJobObject failed: " + Win32(error));

                if (!api.SetDieOnUnhandledException(job, out error))
                    return Unavailable(ref job, "SetInformationJobObject failed: " + Win32(error));

                // Read the flag back. Setting it can succeed on a handle that is not the job
                // we think it is; querying proves the limit really is in place.
                if (!api.QueryHasDieOnUnhandledException(job, out error))
                    return Unavailable(ref job, "the job does not report DIE_ON_UNHANDLED_EXCEPTION: " + Win32(error));

                if (!api.AssignCurrentProcess(job, out error))
                    return Unavailable(ref job, "AssignProcessToJobObject failed: " + Win32(error));

                // Membership in THIS job, not "in some job": an outer job would satisfy the
                // generic check and tell us nothing about our own limit.
                if (!api.IsCurrentProcessInJob(job, out error))
                    return Unavailable(ref job, "the process is not a member of the new job: " + Win32(error));

                var contained = new WerContainment
                {
                    Active = true,
                    JobName = name,
                    Description = "job (crash-UI limit in force, inherited by normal descendants)",
                    _job = job,
                };
                job = null; // ownership moved to the instance
                return contained;
            }
            catch (Exception ex)
            {
                return Unavailable(ref job, "unavailable: " + ex.Message);
            }
        }

        private static WerContainment Unavailable(ref SafeJobHandle job, string reason)
        {
            if (job != null) { try { job.Dispose(); } catch { } job = null; }
            return Inactive("unavailable (" + reason + ")");
        }

        /// <summary>
        /// What the hidden-desktop child reports. It must not create a second job: it already
        /// inherited the parent's.
        ///
        /// The check is deliberately against the NAMED job only. Asking "am I in any job?"
        /// answers yes on an ordinary developer machine - a shell, a terminal or a container
        /// puts processes in a job of its own - so reporting that as containment would claim
        /// a limit this suite never set. A run with containment off must say so.
        /// </summary>
        public static string DescribeInherited(string jobName, WerContainmentMode requested)
        {
            if (requested == WerContainmentMode.Off) return "off";
            try
            {
                if (jobName != null && IsCurrentProcessInNamedJob(jobName))
                    return "job (inherited from the isolation parent, "
                        + (NamedJobHasDieOnUnhandledException(jobName)
                            ? "crash-UI limit in force" : "crash-UI limit NOT in force") + ")";
            }
            catch { /* fall through to the honest answer below */ }
            return "unavailable (not a member of the test job)";
        }

        /// <summary>Open a job by name and ask whether this process belongs to it.</summary>
        public static bool IsCurrentProcessInNamedJob(string jobName)
        {
            if (string.IsNullOrEmpty(jobName)) return false;
            using (SafeJobHandle job = NativeMethods.OpenJobObjectW(NativeMethods.JOB_OBJECT_QUERY, false, jobName))
            {
                if (job.IsInvalid) return false;
                bool member;
                if (!NativeMethods.IsProcessInJob(NativeMethods.GetCurrentProcess(), job.DangerousGetHandle(), out member))
                    return false;
                return member;
            }
        }

        /// <summary>
        /// Whether the named job still carries DIE_ON_UNHANDLED_EXCEPTION. This is the
        /// property that actually contains a crashing member: Windows enforces the job LIMIT.
        ///
        /// The per-process error-mode bit is only how Windows applies that limit at
        /// association time, and a process may change its own error mode afterwards - the
        /// .NET Framework CLR does exactly that during startup, so a managed child can report
        /// an error mode without SEM_NOGPFAULTERRORBOX while still being fully contained.
        /// Assert this, and treat GetErrorMode as diagnostics.
        /// </summary>
        public static bool NamedJobHasDieOnUnhandledException(string jobName)
        {
            if (string.IsNullOrEmpty(jobName)) return false;
            using (SafeJobHandle job = NativeMethods.OpenJobObjectW(NativeMethods.JOB_OBJECT_QUERY, false, jobName))
            {
                if (job.IsInvalid) return false;
                int error;
                return RealJobApi.Instance.QueryHasDieOnUnhandledException(job, out error);
            }
        }

        /// <summary>The current process error mode, for diagnostics (see the method above).</summary>
        public static uint CurrentErrorMode()
        {
            return NativeMethods.GetErrorMode();
        }

        public void Dispose()
        {
            if (_job != null) { try { _job.Dispose(); } catch { } _job = null; }
            Active = false;
        }

        private static string Win32(int error)
        {
            if (error == 0) return "no Win32 error reported";
            try { return new Win32Exception(error).Message + " (" + error + ")"; }
            catch { return "Win32 error " + error; }
        }

        // ---- native seam -------------------------------------------------------

        /// <summary>
        /// The five native steps, behind an interface so the failure paths are testable
        /// without a machine that actually refuses job creation.
        /// </summary>
        internal interface IJobNativeApi
        {
            SafeJobHandle CreateJob(string name, out int error);
            bool SetDieOnUnhandledException(SafeJobHandle job, out int error);
            bool QueryHasDieOnUnhandledException(SafeJobHandle job, out int error);
            bool AssignCurrentProcess(SafeJobHandle job, out int error);
            bool IsCurrentProcessInJob(SafeJobHandle job, out int error);
        }

        internal sealed class RealJobApi : IJobNativeApi
        {
            public static readonly RealJobApi Instance = new RealJobApi();

            public SafeJobHandle CreateJob(string name, out int error)
            {
                SafeJobHandle job = NativeMethods.CreateJobObjectW(IntPtr.Zero, name);
                error = job.IsInvalid ? Marshal.GetLastWin32Error() : 0;
                return job;
            }

            public bool SetDieOnUnhandledException(SafeJobHandle job, out int error)
            {
                var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                info.BasicLimitInformation.LimitFlags = NativeMethods.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
                int size = Marshal.SizeOf(typeof(NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(info, buffer, false);
                    bool ok = NativeMethods.SetInformationJobObject(job,
                        NativeMethods.JobObjectExtendedLimitInformation, buffer, (uint)size);
                    error = ok ? 0 : Marshal.GetLastWin32Error();
                    return ok;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }

            public bool QueryHasDieOnUnhandledException(SafeJobHandle job, out int error)
            {
                int size = Marshal.SizeOf(typeof(NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint returned;
                    if (!NativeMethods.QueryInformationJobObject(job,
                        NativeMethods.JobObjectExtendedLimitInformation, buffer, (uint)size, out returned))
                    {
                        error = Marshal.GetLastWin32Error();
                        return false;
                    }
                    var info = (NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                        Marshal.PtrToStructure(buffer, typeof(NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                    error = 0;
                    return (info.BasicLimitInformation.LimitFlags
                        & NativeMethods.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION) != 0;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }

            public bool AssignCurrentProcess(SafeJobHandle job, out int error)
            {
                bool ok = NativeMethods.AssignProcessToJobObject(job, NativeMethods.GetCurrentProcess());
                error = ok ? 0 : Marshal.GetLastWin32Error();
                return ok;
            }

            public bool IsCurrentProcessInJob(SafeJobHandle job, out int error)
            {
                bool member;
                bool ok = NativeMethods.IsProcessInJob(NativeMethods.GetCurrentProcess(),
                    job.DangerousGetHandle(), out member);
                error = ok ? 0 : Marshal.GetLastWin32Error();
                return ok && member;
            }
        }

        internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeJobHandle() : base(true) { }

            public SafeJobHandle(IntPtr handle, bool ownsHandle) : base(ownsHandle)
            {
                SetHandle(handle);
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            protected override bool ReleaseHandle()
            {
                return NativeMethods.CloseHandle(handle);
            }
        }

        private static class NativeMethods
        {
            public const uint JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
            public const int JobObjectExtendedLimitInformation = 9;
            public const uint JOB_OBJECT_QUERY = 0x0004;
            public const uint SEM_NOGPFAULTERRORBOX = 0x0002;

            [StructLayout(LayoutKind.Sequential)]
            public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                public long PerProcessUserTimeLimit;
                public long PerJobUserTimeLimit;
                public uint LimitFlags;
                public IntPtr MinimumWorkingSetSize;   // SIZE_T
                public IntPtr MaximumWorkingSetSize;   // SIZE_T
                public uint ActiveProcessLimit;
                public IntPtr Affinity;                // ULONG_PTR
                public uint PriorityClass;
                public uint SchedulingClass;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IO_COUNTERS
            {
                public ulong ReadOperationCount;
                public ulong WriteOperationCount;
                public ulong OtherOperationCount;
                public ulong ReadTransferCount;
                public ulong WriteTransferCount;
                public ulong OtherTransferCount;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
                public IO_COUNTERS IoInfo;
                public IntPtr ProcessMemoryLimit;      // SIZE_T
                public IntPtr JobMemoryLimit;          // SIZE_T
                public IntPtr PeakProcessMemoryUsed;   // SIZE_T
                public IntPtr PeakJobMemoryUsed;       // SIZE_T
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern SafeJobHandle CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern SafeJobHandle OpenJobObjectW(uint dwDesiredAccess,
                [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, string lpName);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetInformationJobObject(SafeJobHandle hJob, int infoClass,
                IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool QueryInformationJobObject(SafeJobHandle hJob, int infoClass,
                IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength, out uint lpReturnLength);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool AssignProcessToJobObject(SafeJobHandle hJob, IntPtr hProcess);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool IsProcessInJob(IntPtr processHandle, IntPtr jobHandle,
                [MarshalAs(UnmanagedType.Bool)] out bool result);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll")]
            public static extern uint GetErrorMode();

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseHandle(IntPtr handle);
        }
    }
}
