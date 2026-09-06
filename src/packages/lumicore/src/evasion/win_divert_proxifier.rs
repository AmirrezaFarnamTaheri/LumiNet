//! Process-level WinDivert transparent proxifier.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct WinDivertProxifierConfig {
    pub proxy_port: u16,
    pub include_processes: Vec<String>,
    pub exclude_processes: Vec<String>,
}

use once_cell::sync::Lazy;

static ORIGINAL_DESTINATIONS: Lazy<Mutex<HashMap<u16, (String, u16)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Retrieve original destination for a given local port.
pub fn get_original_destination(local_port: u16) -> Option<(String, u16)> {
    let map = ORIGINAL_DESTINATIONS.lock().ok()?;
    map.get(&local_port).cloned()
}

#[cfg(not(target_os = "windows"))]
pub fn start_win_divert_proxifier(
    _config: WinDivertProxifierConfig,
    _running: Arc<AtomicBool>,
) -> Result<(), String> {
    Err("WinDivert Proxifier is only supported on Windows".to_string())
}

#[cfg(target_os = "windows")]
pub fn start_win_divert_proxifier(
    config: WinDivertProxifierConfig,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    use std::ffi::c_void;
    use std::ptr;

    // WinDivert structures
    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    pub struct DIVERT_ADDRESS {
        pub timestamp: u64,
        pub if_idx: u32,
        pub sub_if_idx: u32,
        pub direction: u8,
        pub bits: u8,
        pub reserved: [u8; 62],
    }

    type DivertOpenFn = unsafe extern "system" fn(
        filter: *const u8,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> *mut c_void;
    type DivertRecvFn = unsafe extern "system" fn(
        handle: *mut c_void,
        packet: *mut u8,
        packet_len: u32,
        read_len: *mut u32,
        addr: *mut DIVERT_ADDRESS,
    ) -> i32;
    type DivertSendFn = unsafe extern "system" fn(
        handle: *mut c_void,
        packet: *const u8,
        packet_len: u32,
        write_len: *mut u32,
        addr: *const DIVERT_ADDRESS,
    ) -> i32;
    type DivertCloseFn = unsafe extern "system" fn(handle: *mut c_void) -> i32;
    type DivertHelperCalcChecksumsFn = unsafe extern "system" fn(
        packet: *mut u8,
        packet_len: u32,
        addr: *mut DIVERT_ADDRESS,
        flags: u64,
    ) -> i32;

    struct WinDivertDll {
        _lib: *mut c_void,
        open: DivertOpenFn,
        recv: DivertRecvFn,
        send: DivertSendFn,
        close: DivertCloseFn,
        calc_checksums: DivertHelperCalcChecksumsFn,
    }

    extern "system" {
        fn LoadLibraryA(lpLibFileName: *const u8) -> *mut c_void;
        fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
        fn FreeLibrary(hLibModule: *mut c_void) -> i32;
    }

    impl WinDivertDll {
        fn load() -> Result<Self, String> {
            unsafe {
                let lib = LoadLibraryA(c"WinDivert.dll".as_ptr().cast());
                if lib.is_null() {
                    return Err("Failed to load WinDivert.dll".to_string());
                }

                let open_ptr = GetProcAddress(lib, c"DivertOpen".as_ptr().cast());
                let recv_ptr = GetProcAddress(lib, c"DivertRecv".as_ptr().cast());
                let send_ptr = GetProcAddress(lib, c"DivertSend".as_ptr().cast());
                let close_ptr = GetProcAddress(lib, c"DivertClose".as_ptr().cast());
                let calc_ptr = GetProcAddress(lib, c"DivertHelperCalcChecksums".as_ptr().cast());

                if open_ptr.is_null()
                    || recv_ptr.is_null()
                    || send_ptr.is_null()
                    || close_ptr.is_null()
                    || calc_ptr.is_null()
                {
                    FreeLibrary(lib);
                    return Err("Failed to find WinDivert functions".to_string());
                }

                Ok(Self {
                    _lib: lib,
                    open: std::mem::transmute::<*mut c_void, DivertOpenFn>(open_ptr),
                    recv: std::mem::transmute::<*mut c_void, DivertRecvFn>(recv_ptr),
                    send: std::mem::transmute::<*mut c_void, DivertSendFn>(send_ptr),
                    close: std::mem::transmute::<*mut c_void, DivertCloseFn>(close_ptr),
                    calc_checksums: std::mem::transmute::<*mut c_void, DivertHelperCalcChecksumsFn>(
                        calc_ptr,
                    ),
                })
            }
        }
    }

    // Windows API helper functions to lookup PID by TCP port
    #[repr(C)]
    struct MIB_TCPROW_OWNER_PID {
        state: u32,
        local_addr: u32,
        local_port: u32,
        remote_addr: u32,
        remote_port: u32,
        owning_pid: u32,
    }

    #[repr(C)]
    struct MIB_TCPTABLE_OWNER_PID {
        num_entries: u32,
        table: [MIB_TCPROW_OWNER_PID; 1],
    }

    type GetExtendedTcpTableFn = unsafe extern "system" fn(
        tcp_table: *mut c_void,
        size: *mut u32,
        order: i32,
        address_family: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;

    type OpenProcessFn = unsafe extern "system" fn(
        desired_access: u32,
        inherit_handle: i32,
        process_id: u32,
    ) -> *mut c_void;

    type GetModuleBaseNameAFn = unsafe extern "system" fn(
        process: *mut c_void,
        module: *mut c_void,
        base_name: *mut u8,
        size: u32,
    ) -> u32;

    type CloseHandleFn = unsafe extern "system" fn(object: *mut c_void) -> i32;

    struct WinHelper {
        get_tcp_table: GetExtendedTcpTableFn,
        open_process: OpenProcessFn,
        get_module_base_name: GetModuleBaseNameAFn,
        close_handle: CloseHandleFn,
    }

    let helper = unsafe {
        let iphlp = LoadLibraryA(c"iphlpapi.dll".as_ptr().cast());
        let kernel32 = LoadLibraryA(c"kernel32.dll".as_ptr().cast());
        let psapi = LoadLibraryA(c"psapi.dll".as_ptr().cast());

        if iphlp.is_null() || kernel32.is_null() || psapi.is_null() {
            return Err("Failed to load Windows networking/psapi DLLs".to_string());
        }

        let tcp_table_ptr = GetProcAddress(iphlp, c"GetExtendedTcpTable".as_ptr().cast());
        let open_proc_ptr = GetProcAddress(kernel32, c"OpenProcess".as_ptr().cast());
        let base_name_ptr = GetProcAddress(psapi, c"GetModuleBaseNameA".as_ptr().cast());
        let close_h_ptr = GetProcAddress(kernel32, c"CloseHandle".as_ptr().cast());

        if tcp_table_ptr.is_null()
            || open_proc_ptr.is_null()
            || base_name_ptr.is_null()
            || close_h_ptr.is_null()
        {
            return Err("Failed to find required Windows API functions".to_string());
        }

        WinHelper {
            get_tcp_table: std::mem::transmute::<*mut c_void, GetExtendedTcpTableFn>(tcp_table_ptr),
            open_process: std::mem::transmute::<*mut c_void, OpenProcessFn>(open_proc_ptr),
            get_module_base_name: std::mem::transmute::<*mut c_void, GetModuleBaseNameAFn>(
                base_name_ptr,
            ),
            close_handle: std::mem::transmute::<*mut c_void, CloseHandleFn>(close_h_ptr),
        }
    };

    let find_pid_by_local_port = |port: u16| -> Option<u32> {
        unsafe {
            let mut size = 0;
            let af_inet = 2; // IPv4
            let tcp_table_owner_pid_all = 5;

            // Query size first
            (helper.get_tcp_table)(
                ptr::null_mut(),
                &mut size,
                1,
                af_inet,
                tcp_table_owner_pid_all,
                0,
            );

            let mut buf = vec![0u8; size as usize];
            let res = (helper.get_tcp_table)(
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
                1,
                af_inet,
                tcp_table_owner_pid_all,
                0,
            );

            if res == 0 {
                let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let entries = std::slice::from_raw_parts(
                    &table.table[0] as *const MIB_TCPROW_OWNER_PID,
                    table.num_entries as usize,
                );

                for entry in entries {
                    // Ports in table are network byte order (Big Endian)
                    let entry_port = u16::from_be(entry.local_port as u16);
                    if entry_port == port {
                        return Some(entry.owning_pid);
                    }
                }
            }
            None
        }
    };

    let get_process_name_by_pid = |pid: u32| -> Option<String> {
        unsafe {
            let process_query_information = 0x0400;
            let process_vm_read = 0x0010;
            let h_process =
                (helper.open_process)(process_query_information | process_vm_read, 0, pid);

            if !h_process.is_null() {
                let mut name_buf = vec![0u8; 260];
                let len = (helper.get_module_base_name)(
                    h_process,
                    ptr::null_mut(),
                    name_buf.as_mut_ptr(),
                    name_buf.len() as u32,
                );

                (helper.close_handle)(h_process);

                if len > 0 {
                    let name = String::from_utf8_lossy(&name_buf[..len as usize]).into_owned();
                    return Some(name.to_lowercase());
                }
            }
            None
        }
    };

    let dll = WinDivertDll::load()?;
    let filter = "outbound and tcp and !loopback and !ip.DstAddr == 127.0.0.1\0";
    let handle = unsafe { (dll.open)(filter.as_ptr(), 0, 0, 0) };
    if handle.is_null() || handle.is_null() {
        return Err("Failed to open outbound WinDivert handle".to_string());
    }

    let mut packet_buf = vec![0u8; 65535];
    let mut addr = DIVERT_ADDRESS {
        timestamp: 0,
        if_idx: 0,
        sub_if_idx: 0,
        direction: 0,
        bits: 0,
        reserved: [0; 62],
    };

    while running.load(Ordering::SeqCst) {
        let mut read_len = 0u32;
        let success = unsafe {
            (dll.recv)(
                handle,
                packet_buf.as_mut_ptr(),
                packet_buf.len() as u32,
                &mut read_len,
                &mut addr,
            )
        };

        if success == 0 {
            thread::sleep(Duration::from_millis(1));
            continue;
        }

        // Parse TCP/IP header (IPv4 offset 20 bytes, TCP ports at offset 20/22)
        if read_len < 40 {
            // Forward small packet
            let mut written = 0u32;
            unsafe {
                (dll.send)(handle, packet_buf.as_ptr(), read_len, &mut written, &addr);
            }
            continue;
        }

        let ip_header_len = ((packet_buf[0] & 0x0F) * 4) as usize;
        if read_len < (ip_header_len + 20) as u32 {
            let mut written = 0u32;
            unsafe {
                (dll.send)(handle, packet_buf.as_ptr(), read_len, &mut written, &addr);
            }
            continue;
        }

        let src_port =
            u16::from_be_bytes([packet_buf[ip_header_len], packet_buf[ip_header_len + 1]]);
        let dst_port =
            u16::from_be_bytes([packet_buf[ip_header_len + 2], packet_buf[ip_header_len + 3]]);

        // Retrieve process matching local TCP source port
        let mut is_match = false;
        if let Some(pid) = find_pid_by_local_port(src_port) {
            if let Some(proc_name) = get_process_name_by_pid(pid) {
                // Check inclusion/exclusion filter
                let included = config.include_processes.is_empty()
                    || config
                        .include_processes
                        .iter()
                        .any(|p| proc_name.contains(&p.to_lowercase()));
                let excluded = !config.exclude_processes.is_empty()
                    && config
                        .exclude_processes
                        .iter()
                        .any(|p| proc_name.contains(&p.to_lowercase()));

                if included && !excluded {
                    is_match = true;
                }
            }
        }

        if is_match {
            // Intercept outbound connection, record original destination
            let dest_ip = format!(
                "{}.{}.{}.{}",
                packet_buf[16], packet_buf[17], packet_buf[18], packet_buf[19]
            );
            if let Ok(mut map) = ORIGINAL_DESTINATIONS.lock() {
                map.insert(src_port, (dest_ip, dst_port));
            }

            // Rewrite destination address to loopback (127.0.0.1) and proxy port
            packet_buf[16] = 127;
            packet_buf[17] = 0;
            packet_buf[18] = 0;
            packet_buf[19] = 1;

            let proxy_port_bytes = config.proxy_port.to_be_bytes();
            packet_buf[ip_header_len + 2] = proxy_port_bytes[0];
            packet_buf[ip_header_len + 3] = proxy_port_bytes[1];

            // Recalculate TCP and IP checksums
            unsafe {
                (dll.calc_checksums)(packet_buf.as_mut_ptr(), read_len, &mut addr, 0);
            }
        }

        // Re-inject/forward packet
        let mut written = 0u32;
        unsafe {
            (dll.send)(handle, packet_buf.as_ptr(), read_len, &mut written, &addr);
        }
    }

    unsafe {
        (dll.close)(handle);
    }
    Ok(())
}
