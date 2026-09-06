//! # Windows Syscall Evasion
//!
//! Direct syscall techniques for Windows API evasion.
//!
//! Note: These techniques are for educational/research purposes and
//! legitimate anti-censorship/anti-fingerprinting use cases.

/// Windows syscall number mapping.
/// Used to call NT API functions directly without going through ntdll.dll imports.
/// This avoids IAT-based detection of sensitive API calls.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NtSyscall {
    /// NtAllocateVirtualMemory
    AllocateVirtualMemory,
    /// NtWriteVirtualMemory
    WriteVirtualMemory,
    /// NtReadVirtualMemory
    ReadVirtualMemory,
    /// NtProtectVirtualMemory
    ProtectVirtualMemory,
    /// NtCreateThreadEx
    CreateThreadEx,
    /// NtOpenProcess
    OpenProcess,
    /// NtClose
    Close,
    /// NtQueryInformationProcess
    QueryInformationProcess,
    /// NtResumeThread
    ResumeThread,
}

/// Syscall Service Number (SSN) for common Windows 10/11 NT API functions.
/// These are the syscall numbers that would normally be resolved from ntdll.dll.
pub fn get_ssn(syscall: NtSyscall) -> u16 {
    match syscall {
        NtSyscall::AllocateVirtualMemory => 0x18,
        NtSyscall::WriteVirtualMemory => 0x3A,
        NtSyscall::ReadVirtualMemory => 0x3F,
        NtSyscall::ProtectVirtualMemory => 0x50,
        NtSyscall::CreateThreadEx => 0xC2,
        NtSyscall::OpenProcess => 0x26,
        NtSyscall::Close => 0x0F,
        NtSyscall::QueryInformationProcess => 0x19,
        NtSyscall::ResumeThread => 0x52,
    }
}

/// PEB (Process Environment Block) walk for API resolution.
/// This technique resolves API addresses by walking the PEB's loaded module list,
/// avoiding the IAT which is monitored by EDR/AV.
///
/// # Safety
/// This function is unsafe and should only be used in controlled environments.
pub unsafe fn resolve_api_from_peb(dll_name: &str, func_name: &str) -> Option<usize> {
    // This is a conceptual implementation
    // Real implementation would:
    // 1. Read PEB from gs:[0x60] (64-bit) or fs:[0x30] (32-bit)
    // 2. Walk PEB->Ldr->InMemoryOrderModuleList
    // 3. Find the target DLL by name
    // 4. Parse its export directory
    // 5. Find the target function by name hash
    let _ = (dll_name, func_name);
    None
}

/// Custom hash function for API name resolution.
/// Uses ROR8 with a configurable seed to hash API names.
pub fn hash_api_name(name: &str, seed: u32) -> u32 {
    let mut hash = seed;
    for byte in name.bytes() {
        // ROR8 (rotate right 8 bits)
        hash = hash.rotate_right(8);
        hash = hash.wrapping_add(byte as u32);
    }
    hash
}

/// Egg hunt technique for finding syscall instructions in memory.
/// Scans a memory region for a specific byte pattern (the "egg") and
/// replaces it with actual syscall instructions at runtime.
///
/// This bypasses static signature detection of syscall instructions on disk.
pub fn find_and_replace_egg(data: &mut [u8], egg: &[u8], replacement: &[u8]) -> usize {
    let mut count = 0;
    let egg_len = egg.len();
    let repl_len = replacement.len();

    if egg_len != repl_len || egg_len == 0 {
        return 0;
    }

    let mut i = 0;
    while i + egg_len <= data.len() {
        if &data[i..i + egg_len] == egg {
            data[i..i + repl_len].copy_from_slice(replacement);
            count += 1;
            i += egg_len;
        } else {
            i += 1;
        }
    }

    count
}

/// Common egg bytes used in syscall stubs (placeholder for syscall instruction).
/// The real syscall instruction (0x0F 0x05) is replaced with these bytes on disk,
/// then patched at runtime.
pub const SYSCALL_EGG: &[u8] = &[0x62, 0x00, 0x00, 0x67];

/// Real syscall + nop + ret instruction sequence.
pub const SYSCALL_REAL: &[u8] = &[0x0F, 0x05, 0xC3];

/// PEB structure offsets for 64-bit Windows.
pub mod peb_offsets {
    /// PEB address (read from gs:[0x60] on 64-bit).
    pub const PEB_OFFSET: u64 = 0x60;
    /// PEB->Ldr offset.
    pub const LDR_OFFSET: u64 = 0x18;
    /// PEB->Ldr->InMemoryOrderModuleList offset.
    pub const IN_MEMORY_ORDER_MODULE_LIST: u64 = 0x20;
    /// LDR_DATA_TABLE_ENTRY->FullDllName offset.
    pub const FULL_DLL_NAME: u64 = 0x48;
    /// LDR_DATA_TABLE_ENTRY->DllBase offset.
    pub const DLL_BASE: u64 = 0x30;
}

/// PE header offsets for export directory parsing.
pub mod pe_offsets {
    /// PE signature offset from module base.
    pub const PE_SIGNATURE: u64 = 0x3C;
    /// Export directory RVA offset from PE header.
    pub const EXPORT_DIR_RVA: u64 = 0x88;
    /// Export directory: number of functions.
    pub const NUMBER_OF_FUNCTIONS: u64 = 0x14;
    /// Export directory: address of functions.
    pub const ADDRESS_OF_FUNCTIONS: u64 = 0x1C;
    /// Export directory: address of names.
    pub const ADDRESS_OF_NAMES: u64 = 0x20;
    /// Export directory: address of name ordinals.
    pub const ADDRESS_OF_NAME_ORDINALS: u64 = 0x24;
}

/// Anti-debug techniques.
pub mod anti_debug {
    /// Checks if a remote debugger is attached.
    /// Uses CheckRemoteDebuggerPresent API.
    pub fn is_debugger_present() -> bool {
        // In real implementation, call Windows API
        false
    }

    /// Checks for common VM indicators in system manufacturer string.
    pub fn is_virtual_machine(manufacturer: &str) -> bool {
        let vm_indicators = [
            "vmware",
            "virtualbox",
            "hyper-v",
            "qemu",
            "xen",
            "kvm",
            "parallels",
            "bhyve",
            "acrn",
        ];
        let lower = manufacturer.to_lowercase();
        vm_indicators.iter().any(|vm| lower.contains(vm))
    }

    /// Checks if system has low RAM (likely VM).
    pub fn is_low_memory(total_ram_mb: u64) -> bool {
        total_ram_mb < 4096
    }
}

/// String obfuscation for API names.
/// Builds strings byte-by-byte to avoid string table detection.
pub struct StringObfuscator {
    bytes: Vec<u8>,
}

impl Default for StringObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl StringObfuscator {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Adds a byte to the obfuscated string.
    pub fn push(&mut self, b: u8) -> &mut Self {
        self.bytes.push(b);
        self
    }

    /// Adds a full string, encoding each byte as individual mov instructions.
    pub fn push_str(&mut self, s: &str) -> &mut Self {
        for b in s.bytes() {
            self.bytes.push(b);
        }
        self.bytes.push(0); // null terminator
        self
    }

    /// Returns the obfuscated bytes.
    pub fn build(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Generates shellcode that builds the string byte-by-byte using mov instructions.
    /// This avoids having the string appear as a contiguous sequence in the binary.
    pub fn generate_mov_shellcode(&self, base_offset: u32) -> Vec<u8> {
        let mut shellcode = Vec::new();
        for (i, &byte) in self.bytes.iter().enumerate() {
            // mov byte ptr [rsp+offset], byte_value
            shellcode.push(0xC6); // mov byte
            shellcode.push(0x44); // modrm
            shellcode.push(0x24); // sib
            shellcode.push((base_offset + i as u32) as u8); // offset
            shellcode.push(byte); // immediate value
        }
        shellcode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_api_name() {
        let hash1 = hash_api_name("NtOpenProcess", 0x92D861F5);
        let hash2 = hash_api_name("NtOpenProcess", 0x92D861F5);
        assert_eq!(hash1, hash2);

        let hash3 = hash_api_name("NtClose", 0x92D861F5);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_find_and_replace_egg() {
        let mut data = vec![0x01, 0x62, 0x00, 0x00, 0x67, 0x02];
        let egg = vec![0x62, 0x00, 0x00, 0x67];
        let replacement = vec![0x0F, 0x05, 0xC3, 0x90];
        let count = find_and_replace_egg(&mut data, &egg, &replacement);
        assert_eq!(count, 1);
        assert_eq!(data[1..5], [0x0F, 0x05, 0xC3, 0x90]);
    }

    #[test]
    fn test_ssn_mapping() {
        assert_eq!(get_ssn(NtSyscall::OpenProcess), 0x26);
        assert_eq!(get_ssn(NtSyscall::AllocateVirtualMemory), 0x18);
    }

    #[test]
    fn test_vm_detection() {
        assert!(anti_debug::is_virtual_machine("VMware Virtual Platform"));
        assert!(anti_debug::is_virtual_machine("VirtualBox"));
        assert!(!anti_debug::is_virtual_machine("Standard PC"));
    }

    #[test]
    fn test_string_obfuscator() {
        let mut obf = StringObfuscator::new();
        obf.push_str("kernel32.dll");
        let bytes = obf.build();
        assert!(bytes.contains(&b'k'));
        assert!(bytes.contains(&b'\0')); // null terminator
    }
}
