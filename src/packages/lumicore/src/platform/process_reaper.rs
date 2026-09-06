use std::fs;
use std::path::{Path, PathBuf};

/// Computes the path to a designated PID lockfile.
pub fn pid_file_path(data_dir: &Path, service_name: &str) -> PathBuf {
    let filename = format!("{}.pid", service_name);
    data_dir.join(filename)
}

/// Records a process PID into a designated lockfile.
pub fn write_pid(data_dir: &Path, service_name: &str, pid: u32) -> std::io::Result<()> {
    fs::write(pid_file_path(data_dir, service_name), pid.to_string())
}

/// Clears an existing PID lockfile if present.
pub fn clear_pid(data_dir: &Path, service_name: &str) -> std::io::Result<()> {
    let path = pid_file_path(data_dir, service_name);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Reads the PID stored in a lockfile, if valid and parseable.
pub fn read_pid(data_dir: &Path, service_name: &str) -> Option<u32> {
    let path = pid_file_path(data_dir, service_name);
    let contents = fs::read_to_string(path).ok()?;
    contents.trim().parse::<u32>().ok()
}

/// Checks whether a given PID corresponds to an actively running OS process.
#[cfg(unix)]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Checks whether a given PID corresponds to an actively running OS process.
#[cfg(windows)]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}")])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
pub fn is_pid_alive(_pid: u32) -> bool {
    false
}

/// Terminates an OS process by PID forcefully.
#[cfg(unix)]
pub fn kill_pid(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Terminates an OS process by PID forcefully.
#[cfg(windows)]
pub fn kill_pid(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
pub fn kill_pid(_pid: u32) -> bool {
    false
}

/// Reaps any orphan sidecar or core process recorded from a previous crash.
/// Returns Some(pid) if an orphan was found and reaped, or None if clean.
pub fn reap_orphan_process(data_dir: &Path, service_name: &str) -> Option<u32> {
    let pid = read_pid(data_dir, service_name)?;
    let mut reaped = None;

    if is_pid_alive(pid) {
        kill_pid(pid);
        reaped = Some(pid);
    }

    let _ = clear_pid(data_dir, service_name);
    reaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_read_write_cycle() {
        let temp_dir = std::env::temp_dir().join(format!("lumitest_reaper_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let service = "test_core";
        assert_eq!(read_pid(&temp_dir, service), None);

        write_pid(&temp_dir, service, 12345).unwrap();
        assert_eq!(read_pid(&temp_dir, service), Some(12345));

        clear_pid(&temp_dir, service).unwrap();
        assert_eq!(read_pid(&temp_dir, service), None);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn own_process_is_alive() {
        let own_pid = std::process::id();
        assert!(is_pid_alive(own_pid));
    }

    #[test]
    fn non_existent_pid_is_not_alive() {
        // PID 9999999 is almost certainly non-existent
        assert!(!is_pid_alive(9999999));
    }
}
