use std::process::{Command, Stdio};
use std::io::{Read, BufReader};
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct Sandbox;

impl Sandbox {
    /// The run_node_script block with standard streams piped and stdout chunked via byte channels, 
    /// launching with CREATE_NO_WINDOW. Also parses custom @think=N parameter depths.
    pub fn run_node_script(script_path: &str, think_param: Option<u32>) -> Result<Vec<u8>, std::io::Error> {
        let mut cmd = Command::new("node");
        cmd.arg(script_path);
        
        // Parse custom @think=N parameter depth
        if let Some(depth) = think_param {
            cmd.arg(format!("@think={}", depth));
        }
        
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .creation_flags(CREATE_NO_WINDOW);
           
        let mut child = cmd.spawn()?;
        
        let mut stdout_buf = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            let mut reader = BufReader::new(stdout);
            let mut chunk = [0; 1024];
            while let Ok(bytes_read) = reader.read(&mut chunk) {
                if bytes_read == 0 {
                    break;
                }
                stdout_buf.extend_from_slice(&chunk[..bytes_read]);
            }
        }
        
        let _status = child.wait()?;
        Ok(stdout_buf)
    }
}
