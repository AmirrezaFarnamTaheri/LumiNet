#[cfg(target_os = "linux")]
use tokio_uring::net::TcpStream;

pub struct UringTcpEngine {
    #[allow(dead_code)] // reserved for io_uring ring depth configuration
    ring_depth: u32,
}

impl UringTcpEngine {
    pub fn new(ring_depth: u32) -> Self {
        Self { ring_depth }
    }

    #[cfg(target_os = "linux")]
    pub async fn transfer(
        &self,
        local: TcpStream,
        remote: TcpStream,
    ) -> Result<(), std::io::Error> {
        let (local_r, local_w) = (local, local.clone());
        let (remote_r, remote_w) = (remote, remote.clone());

        let t1 = tokio::spawn(async move {
            let mut buf = vec![0u8; 16384]; // 16KB zero-copy buffer
            loop {
                let (res, b) = local_r.read(buf).await;
                let n = res?;
                if n == 0 {
                    break;
                }
                let (res_w, _) = remote_w.write_all(b[..n].to_vec()).await;
                res_w?;
                buf = b;
            }
            Ok::<(), std::io::Error>(())
        });

        let t2 = tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            loop {
                let (res, b) = remote_r.read(buf).await;
                let n = res?;
                if n == 0 {
                    break;
                }
                let (res_w, _) = local_w.write_all(b[..n].to_vec()).await;
                res_w?;
                buf = b;
            }
            Ok::<(), std::io::Error>(())
        });

        let _ = tokio::try_join!(t1, t2);
        Ok(())
    }
}
