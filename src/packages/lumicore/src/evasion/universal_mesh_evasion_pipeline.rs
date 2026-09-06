// Pure Rust implementation: Universal Mesh Evasion Pipeline (Batch 10 Synthesis C1)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineMode {
    DirectMesh,
    HolePunchedMesh,
    DpiEvadedMesh,
    StealthBridgeFallback,
}

#[derive(Debug, Clone)]
pub struct PipelineMetrics {
    pub packets_processed: u64,
    pub mode_switches: u32,
    pub current_mode: PipelineMode,
}

pub struct UniversalMeshEvasionPipeline {
    pub peer_id: String,
    pub consecutive_errors: u32,
    pub metrics: PipelineMetrics,
}

impl UniversalMeshEvasionPipeline {
    pub const ERROR_ESCALATION_THRESHOLD: u32 = 3;

    pub fn new(peer_id: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            consecutive_errors: 0,
            metrics: PipelineMetrics {
                packets_processed: 0,
                mode_switches: 0,
                current_mode: PipelineMode::DirectMesh,
            },
        }
    }

    pub fn process_outbound_frame(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        self.metrics.packets_processed += 1;

        match self.metrics.current_mode {
            PipelineMode::DirectMesh | PipelineMode::HolePunchedMesh => {
                // Direct encapsulation
                vec![frame.to_vec()]
            }
            PipelineMode::DpiEvadedMesh => {
                // Fragment frame into 2 segments if larger than 8 bytes
                if frame.len() > 8 {
                    let mid = frame.len() / 2;
                    vec![frame[..mid].to_vec(), frame[mid..].to_vec()]
                } else {
                    vec![frame.to_vec()]
                }
            }
            PipelineMode::StealthBridgeFallback => {
                // Wrap frame with stealth prefix
                let mut wrapped = Vec::with_capacity(frame.len() + 4);
                wrapped.extend_from_slice(b"STH:");
                wrapped.extend_from_slice(frame);
                vec![wrapped]
            }
        }
    }

    pub fn report_transmission_failure(&mut self) -> PipelineMode {
        self.consecutive_errors += 1;

        if self.consecutive_errors >= Self::ERROR_ESCALATION_THRESHOLD {
            self.consecutive_errors = 0;
            let next_mode = match self.metrics.current_mode {
                PipelineMode::DirectMesh => PipelineMode::HolePunchedMesh,
                PipelineMode::HolePunchedMesh => PipelineMode::DpiEvadedMesh,
                PipelineMode::DpiEvadedMesh => PipelineMode::StealthBridgeFallback,
                PipelineMode::StealthBridgeFallback => PipelineMode::StealthBridgeFallback,
            };

            if next_mode != self.metrics.current_mode {
                self.metrics.current_mode = next_mode;
                self.metrics.mode_switches += 1;
            }
        }

        self.metrics.current_mode
    }

    pub fn report_transmission_success(&mut self) {
        self.consecutive_errors = 0;
    }

    pub fn manual_set_mode(&mut self, mode: PipelineMode) {
        if self.metrics.current_mode != mode {
            self.metrics.current_mode = mode;
            self.metrics.mode_switches += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_escalation() {
        let mut pipeline = UniversalMeshEvasionPipeline::new("peer-alpha");
        assert_eq!(pipeline.metrics.current_mode, PipelineMode::DirectMesh);

        // Process direct
        let frames = pipeline.process_outbound_frame(b"PAYLOAD12345");
        assert_eq!(frames.len(), 1);

        // 3 failures escalate to HolePunchedMesh
        pipeline.report_transmission_failure();
        pipeline.report_transmission_failure();
        let mode1 = pipeline.report_transmission_failure();
        assert_eq!(mode1, PipelineMode::HolePunchedMesh);

        // 3 more failures escalate to DpiEvadedMesh
        pipeline.report_transmission_failure();
        pipeline.report_transmission_failure();
        let mode2 = pipeline.report_transmission_failure();
        assert_eq!(mode2, PipelineMode::DpiEvadedMesh);

        // In DpiEvadedMesh, packets are fragmented
        let evaded_frames = pipeline.process_outbound_frame(b"PAYLOAD12345");
        assert_eq!(evaded_frames.len(), 2);

        // 3 more failures escalate to StealthBridgeFallback
        pipeline.report_transmission_failure();
        pipeline.report_transmission_failure();
        let mode3 = pipeline.report_transmission_failure();
        assert_eq!(mode3, PipelineMode::StealthBridgeFallback);

        let stealth_frames = pipeline.process_outbound_frame(b"PAYLOAD12345");
        assert!(stealth_frames[0].starts_with(b"STH:"));
    }
}
