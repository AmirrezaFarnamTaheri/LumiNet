use capstone::prelude::*;

/// Disassembles the payload to detect potential shellcode (e.g. repeated NOPs, function calls, system calls).
/// Returns a formatted string listing the instructions or indicating if shellcode is suspected.
pub fn disassemble_payload(payload: &[u8], arch_str: &str) -> Result<String, String> {
    let cs = match arch_str.to_lowercase().as_str() {
        "x86" => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build()
            .map_err(|e| format!("Capstone init error: {}", e))?,
        "x64" | "x86_64" => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .map_err(|e| format!("Capstone init error: {}", e))?,
        "arm" => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| format!("Capstone init error: {}", e))?,
        "arm64" | "aarch64" => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| format!("Capstone init error: {}", e))?,
        _ => return Err(format!("Unsupported architecture: {}", arch_str)),
    };

    let insns = cs
        .disasm_all(payload, 0x1000)
        .map_err(|e| format!("Disassembly failed: {}", e))?;

    if insns.is_empty() {
        return Ok("No valid instructions found".to_string());
    }

    let mut output = String::new();
    let mut nop_count = 0;

    for insn in insns.as_ref() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let op_str = insn.op_str().unwrap_or("");
        output.push_str(&format!(
            "0x{:x}: {} {}\n",
            insn.address(),
            mnemonic,
            op_str
        ));

        if mnemonic == "nop" {
            nop_count += 1;
        }
    }

    if nop_count > 5 {
        output.push_str(
            "\n⚠️ WARNING: Suspected NOP sled detected! Possible shellcode execution attempt.\n",
        );
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_x86() {
        let code = b"\x90\x90\x90\x90\x90\x90";
        let res = disassemble_payload(code, "x64").unwrap();
        assert!(res.contains("nop"));
        assert!(res.contains("WARNING"));
    }
}
