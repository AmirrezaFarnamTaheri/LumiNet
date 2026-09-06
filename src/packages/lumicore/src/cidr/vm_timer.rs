pub struct VmDetector;

impl VmDetector {
    /// Detects hypervisors by measuring latency diffs over CPUID calls.
    pub fn detect_hypervisor() -> bool {
        if !cfg!(target_arch = "x86_64") {
            return false;
        }

        let t1 = Self::check_rdtsc_diff();
        // Trigger hypervisor interception loop
        for _ in 0..10 {
            unsafe {
                std::arch::asm!(
                    "push rbx",
                    "xor eax, eax",
                    "cpuid",
                    "pop rbx",
                    out("eax") _,
                    out("ecx") _,
                    out("edx") _,
                );
            }
        }
        let t2 = Self::check_rdtsc_diff();

        // If elapsed cycles > 10,000, context switching occurred (sandbox/VM trap)
        (t2 - t1) > 10000
    }

    #[inline(always)]
    fn check_rdtsc_diff() -> u64 {
        let low: u32;
        let high: u32;
        unsafe {
            std::arch::asm!(
                "rdtsc",
                out("eax") low,
                out("edx") high,
            );
        }
        ((high as u64) << 32) | (low as u64)
    }
}
