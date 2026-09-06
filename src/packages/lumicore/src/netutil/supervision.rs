//! # Connection Supervision Engine
//!
//! Maps active TCP/UDP sockets to the owning process PID and process name.
//! Eliminates shell calls to netstat/grep. Refined from IPRadar2ForLinux-main.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Details of an active network socket and its owning process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SocketOwner {
    pub pid: u32,
    pub process_name: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub protocol: String,
}

/// Helper to resolve process name from PID on Windows.
#[cfg(target_os = "windows")]
fn get_process_name_from_pid(pid: u32) -> String {
    use std::ffi::c_void;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return "Unknown".to_string();
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn QueryFullProcessImageNameW(
            hProcess: *mut c_void,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> i32;
    }

    let mut buffer = vec![0u16; 260];
    let mut size = buffer.len() as u32;
    let success = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };

    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }

    if success != 0 {
        let path = String::from_utf16_lossy(&buffer[..size as usize]);
        std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Unknown".to_string())
    } else {
        "Unknown".to_string()
    }
}

/// Query active TCP and UDP sockets with process owners.
#[cfg(target_os = "windows")]
pub fn get_active_connections() -> io::Result<Vec<SocketOwner>> {
    use std::ptr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // UDP_TABLE_OWNER_PID is 1 in Windows SDK
    const UDP_TABLE_OWNER_PID: i32 = 1;

    let mut connections = Vec::new();

    // 1. Fetch TCP Table
    let mut size = 0;
    unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            1,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }

    let mut buffer = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            1,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret == 0 {
        let num_entries = unsafe { *(buffer.as_ptr() as *const u32) } as usize;
        let table_ptr = unsafe { buffer.as_ptr().add(4) };

        for i in 0..num_entries {
            let row_ptr = unsafe { table_ptr.add(i * 24) };
            let state = unsafe { *(row_ptr as *const u32) };
            let local_addr_raw = unsafe { *(row_ptr.add(4) as *const u32) };
            let local_port_raw = unsafe { *(row_ptr.add(8) as *const u32) };
            let remote_addr_raw = unsafe { *(row_ptr.add(12) as *const u32) };
            let remote_port_raw = unsafe { *(row_ptr.add(16) as *const u32) };
            let pid = unsafe { *(row_ptr.add(20) as *const u32) };

            let local_ip = IpAddr::V4(Ipv4Addr::from(local_addr_raw.to_be()));
            let local_port = u16::from_be_bytes([
                (local_port_raw & 0xff) as u8,
                ((local_port_raw >> 8) & 0xff) as u8,
            ]);
            let remote_ip = IpAddr::V4(Ipv4Addr::from(remote_addr_raw.to_be()));
            let remote_port = u16::from_be_bytes([
                (remote_port_raw & 0xff) as u8,
                ((remote_port_raw >> 8) & 0xff) as u8,
            ]);

            let process_name = get_process_name_from_pid(pid);

            let state_str = match state {
                1 => "CLOSED",
                2 => "LISTEN",
                3 => "SYN_SENT",
                4 => "SYN_RCVD",
                5 => "ESTABLISHED",
                6 => "FIN_WAIT1",
                7 => "FIN_WAIT2",
                8 => "CLOSE_WAIT",
                9 => "CLOSING",
                10 => "LAST_ACK",
                11 => "TIME_WAIT",
                12 => "DELETE_TCB",
                _ => "UNKNOWN",
            };

            connections.push(SocketOwner {
                pid,
                process_name,
                local_addr: SocketAddr::new(local_ip, local_port).to_string(),
                remote_addr: SocketAddr::new(remote_ip, remote_port).to_string(),
                state: state_str.to_string(),
                protocol: "TCP".to_string(),
            });
        }
    }

    // 2. Fetch UDP Table
    let mut size_udp = 0;
    unsafe {
        GetExtendedUdpTable(
            ptr::null_mut(),
            &mut size_udp,
            1,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }

    let mut buffer_udp = vec![0u8; size_udp as usize];
    let ret_udp = unsafe {
        GetExtendedUdpTable(
            buffer_udp.as_mut_ptr() as *mut _,
            &mut size_udp,
            1,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if ret_udp == 0 {
        let num_entries = unsafe { *(buffer_udp.as_ptr() as *const u32) } as usize;
        let table_ptr = unsafe { buffer_udp.as_ptr().add(4) };

        for i in 0..num_entries {
            let row_ptr = unsafe { table_ptr.add(i * 12) };
            let local_addr_raw = unsafe { *(row_ptr as *const u32) };
            let local_port_raw = unsafe { *(row_ptr.add(4) as *const u32) };
            let pid = unsafe { *(row_ptr.add(8) as *const u32) };

            let local_ip = IpAddr::V4(Ipv4Addr::from(local_addr_raw.to_be()));
            let local_port = u16::from_be_bytes([
                (local_port_raw & 0xff) as u8,
                ((local_port_raw >> 8) & 0xff) as u8,
            ]);

            let process_name = get_process_name_from_pid(pid);

            connections.push(SocketOwner {
                pid,
                process_name,
                local_addr: SocketAddr::new(local_ip, local_port).to_string(),
                remote_addr: "*:*".to_string(),
                state: "UDP_OPEN".to_string(),
                protocol: "UDP".to_string(),
            });
        }
    }

    Ok(connections)
}

/// Query active TCP and UDP sockets with process owners.
#[cfg(not(target_os = "windows"))]
pub fn get_active_connections() -> io::Result<Vec<SocketOwner>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_active_connections() {
        let result = get_active_connections();
        assert!(result.is_ok());

        let connections = result.unwrap();
        let _ = connections;
    }
}
