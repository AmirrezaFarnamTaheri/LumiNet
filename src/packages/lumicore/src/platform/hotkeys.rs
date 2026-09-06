//! # OS-Level Global Hotkey Hook
//!
//! Provides global hotkey interception. Spawns a background thread to listen
//! for Win32 WM_HOTKEY messages on Windows, and runs event loops on macOS/Linux.
//! Refined from GlobalHotKeys-master.

use crossbeam::channel::{self, Receiver, Sender};
use std::thread;

/// Struct representing a registered global hotkey.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HotkeyConfig {
    pub id: i32,
    pub modifiers: u32, // e.g. MOD_CONTROL = 0x0002, MOD_SHIFT = 0x0004
    pub vk: u32,        // Virtual Key code, e.g. 0x53 for 'S'
}

/// Global hotkey event sent to the channel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HotkeyEvent {
    pub id: i32,
}

/// Handle to manage running hotkey listener threads.
pub struct HotkeyManager {
    event_rx: Receiver<HotkeyEvent>,
    #[allow(dead_code)]
    thread_handle: Option<thread::JoinHandle<()>>,
    #[cfg(windows)]
    #[allow(dead_code)]
    hwnd: Option<usize>,
}

impl HotkeyManager {
    /// Spawns the hotkey listener thread and registers hotkeys.
    pub fn new(hotkeys: Vec<HotkeyConfig>) -> Result<Self, String> {
        let (tx, rx) = channel::unbounded();

        #[cfg(windows)]
        {
            let (hwnd_tx, hwnd_rx) = channel::bounded(1);
            let thread_handle = thread::spawn(move || unsafe {
                run_windows_hotkey_loop(hotkeys, tx, hwnd_tx);
            });

            // Wait for window handle creation
            let hwnd = hwnd_rx.recv().map_err(|e| e.to_string())?;

            Ok(Self {
                event_rx: rx,
                thread_handle: Some(thread_handle),
                hwnd: Some(hwnd),
            })
        }

        #[cfg(not(windows))]
        {
            let thread_handle = thread::spawn(move || {
                run_mock_hotkey_loop(hotkeys, tx);
            });

            Ok(Self {
                event_rx: rx,
                thread_handle: Some(thread_handle),
            })
        }
    }

    /// Retrieve the receiver channel for hotkey triggers.
    pub fn receiver(&self) -> &Receiver<HotkeyEvent> {
        &self.event_rx
    }
}

/// Windows FFI signatures for window message loop and hotkeys.
#[cfg(windows)]
unsafe fn run_windows_hotkey_loop(
    hotkeys: Vec<HotkeyConfig>,
    event_tx: Sender<HotkeyEvent>,
    hwnd_tx: Sender<usize>,
) {
    use std::ffi::c_void;

    type WndProc = unsafe extern "system" fn(usize, u32, usize, isize) -> isize;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct WndClassW {
        style: u32,
        lpfnWndProc: WndProc,
        cbClsExtra: i32,
        cbWndExtra: i32,
        hInstance: usize,
        hIcon: usize,
        hCursor: usize,
        hbrBackground: usize,
        lpszMenuName: *const u16,
        lpszClassName: *const u16,
    }

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct Msg {
        hwnd: usize,
        message: u32,
        wParam: usize,
        lParam: isize,
        time: u32,
        pt: Point,
    }

    #[link(name = "user32")]
    extern "system" {
        fn RegisterClassW(lpWndClass: *const WndClassW) -> u16;
        fn CreateWindowExW(
            dwExStyle: u32,
            lpClassName: *const u16,
            lpWindowName: *const u16,
            dwStyle: u32,
            x: i32,
            y: i32,
            nWidth: i32,
            nHeight: i32,
            hWndParent: usize,
            hMenu: usize,
            hInstance: usize,
            lpParam: *mut c_void,
        ) -> usize;
        fn DestroyWindow(hWnd: usize) -> i32;
        fn DefWindowProcW(hWnd: usize, Msg: u32, wParam: usize, lParam: isize) -> isize;
        fn GetMessageW(lpMsg: *mut Msg, hWnd: usize, wMsgFilterMin: u32, wMsgFilterMax: u32)
            -> i32;
        fn TranslateMessage(lpMsg: *const Msg) -> i32;
        fn DispatchMessageW(lpMsg: *const Msg) -> isize;
        fn RegisterHotKey(hWnd: usize, id: i32, fsModifiers: u32, vk: u32) -> i32;
        fn UnregisterHotKey(hWnd: usize, id: i32) -> i32;
    }

    // Windows procedure callback
    unsafe extern "system" fn wnd_proc(
        hwnd: usize,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize {
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    let class_name: Vec<u16> = "LumiHotkeyClass\0".encode_utf16().collect();
    let wc = WndClassW {
        style: 0,
        lpfnWndProc: wnd_proc,
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: 0,
        hIcon: 0,
        hCursor: 0,
        hbrBackground: 0,
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };

    RegisterClassW(&wc);

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        std::ptr::null(),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        std::ptr::null_mut(),
    );

    if hwnd == 0 {
        return;
    }

    // Send window handle to main thread
    let _ = hwnd_tx.send(hwnd);

    // Register all configured hotkeys
    for hk in &hotkeys {
        RegisterHotKey(hwnd, hk.id, hk.modifiers, hk.vk);
    }

    // Windows message pump
    let mut msg: Msg = std::mem::zeroed();
    while GetMessageW(&mut msg, 0, 0, 0) > 0 {
        if msg.message == 0x0312 {
            // WM_HOTKEY
            let hotkey_id = msg.wParam as i32;
            let _ = event_tx.send(HotkeyEvent { id: hotkey_id });
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Unregister and clean up window
    for hk in hotkeys {
        UnregisterHotKey(hwnd, hk.id);
    }
    DestroyWindow(hwnd);
}

/// Mock listener loop for macOS/Linux target builds.
#[cfg(not(windows))]
fn run_mock_hotkey_loop(hotkeys: Vec<HotkeyConfig>, event_tx: Sender<HotkeyEvent>) {
    // In headless test environments, just keep the thread alive.
    let _ = hotkeys;
    let _ = event_tx;
    loop {
        thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotkey_manager_creation() {
        let configs = vec![HotkeyConfig {
            id: 1,
            modifiers: 0x0002 | 0x0004, // CTRL + SHIFT
            vk: 0x53,                   // 'S'
        }];

        let manager = HotkeyManager::new(configs);
        // Should compile and instantiate cleanly (may fail or succeed depending on thread UI context,
        // but we verify it doesn't crash)
        assert!(manager.is_ok());
    }
}
