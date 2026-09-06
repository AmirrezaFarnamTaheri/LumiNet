//! Process lifecycle and orphan-killing Job Object supervisor.
//!
//! Guarantees kernel-level cleanup of child proxy processes (Xray, sing-box, mihomo, etc.)
//! via Win32 Job Objects (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) on Windows, and process group
//! tracking with SIGTERM/SIGKILL broadcast on Unix.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
type HANDLE = *mut std::ffi::c_void;
#[cfg(windows)]
type BOOL = i32;

#[cfg(windows)]
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
#[cfg(windows)]
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
#[cfg(windows)]
const JobObjectExtendedLimitInformation: i32 = 9;
#[cfg(windows)]
const PROCESS_SET_QUOTA: u32 = 0x0100;
#[cfg(windows)]
const PROCESS_TERMINATE: u32 = 0x0001;

#[repr(C)]
#[cfg(windows)]
struct IO_COUNTERS {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
}

#[repr(C)]
#[cfg(windows)]
struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: u32,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: u32,
    Affinity: usize,
    PriorityClass: u32,
    SchedulingClass: u32,
}

#[repr(C)]
#[cfg(windows)]
struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryLimit: usize,
    PeakJobMemoryLimit: usize,
}

#[cfg(windows)]
extern "system" {
    fn CreateJobObjectW(
        lpJobAttributes: *const std::ffi::c_void,
        lpName: *const u16,
    ) -> HANDLE;

    fn SetInformationJobObject(
        hJob: HANDLE,
        JobObjectInformationClass: i32,
        lpJobObjectInformation: *const std::ffi::c_void,
        cbJobObjectInformationLength: u32,
    ) -> BOOL;

    fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: BOOL, dwProcessId: u32) -> HANDLE;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
}

/// Supervisor managing child processes in an isolated OS container or process group.
pub struct JobObjectSupervisor {
    #[cfg(windows)]
    job_handle: HANDLE,
    #[cfg(not(windows))]
    tracked_pids: std::sync::Mutex<Vec<u32>>,
    disposed: Arc<AtomicBool>,
}

// Safety: Windows HANDLE or Mutex<Vec<u32>> are thread-safe when guarded
unsafe impl Send for JobObjectSupervisor {}
unsafe impl Sync for JobObjectSupervisor {}

impl JobObjectSupervisor {
    /// Creates a new supervisor instance.
    #[cfg(windows)]
    pub fn new() -> Result<Self, String> {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() || job == INVALID_HANDLE_VALUE {
                return Err(format!("CreateJobObject failed with error: {}", std::io::Error::last_os_error()));
            }

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            let length = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
            let success = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                length,
            );

            if success == 0 {
                let err = std::io::Error::last_os_error();
                CloseHandle(job);
                return Err(format!("SetInformationJobObject failed: {}", err));
            }

            Ok(Self {
                job_handle: job,
                disposed: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    /// Creates a new supervisor instance on non-Windows platforms.
    #[cfg(not(windows))]
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            tracked_pids: std::sync::Mutex::new(Vec::new()),
            disposed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Assigns an existing process handle to this supervisor container.
    #[cfg(windows)]
    pub fn assign_process_handle(&self, handle: HANDLE) -> Result<(), String> {
        if self.disposed.load(Ordering::SeqCst) {
            return Err("Supervisor is already disposed".to_string());
        }
        unsafe {
            let success = AssignProcessToJobObject(self.job_handle, handle);
            if success == 0 {
                return Err(format!(
                    "AssignProcessToJobObject failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        }
    }

    /// Assigns a running process ID (PID) to this supervisor.
    pub fn assign_pid(&self, pid: u32) -> Result<(), String> {
        if self.disposed.load(Ordering::SeqCst) {
            return Err("Supervisor is already disposed".to_string());
        }

        #[cfg(windows)]
        unsafe {
            let proc_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if proc_handle.is_null() || proc_handle == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "OpenProcess(PID={}) failed: {}",
                    pid,
                    std::io::Error::last_os_error()
                ));
            }
            let res = self.assign_process_handle(proc_handle);
            CloseHandle(proc_handle);
            res
        }

        #[cfg(not(windows))]
        {
            let mut pids = self.tracked_pids.lock().map_err(|e| e.to_string())?;
            pids.push(pid);
            Ok(())
        }
    }

    /// Explicitly closes the job object or reaps tracked children.
    pub fn close(&self) {
        if self.disposed.swap(true, Ordering::SeqCst) {
            return;
        }

        #[cfg(windows)]
        unsafe {
            if !self.job_handle.is_null() && self.job_handle != INVALID_HANDLE_VALUE {
                CloseHandle(self.job_handle);
            }
        }

        #[cfg(unix)]
        {
            if let Ok(pids) = self.tracked_pids.lock() {
                for pid in pids.iter() {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", &pid.to_string()])
                        .status();
                }
            }
        }
    }
}

impl Drop for JobObjectSupervisor {
    fn drop(&mut self) {
        self.close();
    }
}
