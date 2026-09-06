// Ported from: l7-snake-main
// Target path: core/src/proxy/l7_interceptor.rs

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Configuration for the L7 Snake Tracer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7SnakeConfig {
    pub id: String,
    pub listen_port: u16,
    pub targets: Vec<String>,
    pub routes: Vec<String>,
    pub terminator: bool,
    pub interval_secs: u64,
}

impl Default for L7SnakeConfig {
    fn default() -> Self {
        Self {
            id: "none".to_string(),
            listen_port: 9001,
            targets: vec!["127.0.0.1:9002".to_string()],
            routes: vec!["route-a".to_string(), "route-b".to_string()],
            terminator: true,
            interval_secs: 3,
        }
    }
}

/// Status chain structure matching protoraw status.proto message fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusChain {
    pub id: String,
    pub terminator: bool,
    pub last_updated: String,
    pub health: i32, // 0 = HEALTHY, 1 = OFFLINE, 2 = UNHEALTHY
    pub targets: i32,
    pub routes: Vec<String>,
}

/// Echo request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoRequest {
    pub echo: String,
}

/// L7 Interceptor implementing path tracing and health tracking
pub struct L7Interceptor {
    pub config: Arc<Mutex<L7SnakeConfig>>,
    pub central_data: Arc<Mutex<Vec<StatusChain>>>,
}

impl L7Interceptor {
    /// Creates a new L7Interceptor instance
    pub fn new() -> Self {
        let default_cfg = L7SnakeConfig::default();
        let initial_own_data = Self::build_own_data(&default_cfg);
        Self {
            config: Arc::new(Mutex::new(default_cfg)),
            central_data: Arc::new(Mutex::new(vec![initial_own_data])),
        }
    }

    /// Update configuration settings
    pub fn update_config(&self, new_config: L7SnakeConfig) {
        if let Ok(mut cfg) = self.config.lock() {
            *cfg = new_config;
        }
    }

    /// Returns the formatting timestamp string
    fn get_formatted_time() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown_time".to_string())
    }

    /// Build local node status data
    fn build_own_data(config: &L7SnakeConfig) -> StatusChain {
        StatusChain {
            id: config.id.clone(),
            terminator: config.terminator,
            last_updated: Self::get_formatted_time(),
            health: 1, // Start offline until probed or probes complete
            targets: config.targets.len() as i32,
            routes: config.routes.clone(),
        }
    }

    /// Get human readable health status representation
    fn get_health_human(health_code: i32) -> &'static str {
        match health_code {
            0 => "HEALTHY",
            1 => "OFFLINE",
            2 => "UNHEALTHY",
            _ => "UNKNOWN",
        }
    }

    /// Main API intercept call
    pub fn intercept(&self) {
        println!("L7Interceptor: Intercepting network traffic and executing L7 trace loops");
    }

    /// Starts both client and server background tasks
    pub async fn start_interceptor(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config_clone = Arc::clone(&self.config);
        let data_clone = Arc::clone(&self.central_data);

        // Spawn client tracing loop
        tokio::spawn(async move {
            if let Err(e) = Self::run_client_loop(config_clone, data_clone).await {
                log::error!("L7Interceptor: client loop failed: {:?}", e);
            }
        });

        let config_server = Arc::clone(&self.config);
        let data_server = Arc::clone(&self.central_data);

        // Spawn server service
        tokio::spawn(async move {
            if let Err(e) = Self::run_server_service(config_server, data_server).await {
                log::error!("L7Interceptor: server service failed: {:?}", e);
            }
        });

        Ok(())
    }

    /// Client loop that pokes targets periodically
    async fn run_client_loop(
        config: Arc<Mutex<L7SnakeConfig>>,
        central_data: Arc<Mutex<Vec<StatusChain>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let (targets, interval_secs) = {
                if let Ok(cfg) = config.lock() {
                    (cfg.targets.clone(), cfg.interval_secs)
                } else {
                    (vec![], 3)
                }
            };

            let mut connection_pool_count = 0;
            let mut gathered_chains = Vec::new();

            // Perform poke queries to targets
            for target in &targets {
                match Self::poke_target(target).await {
                    Ok(mut sub_chains) => {
                        connection_pool_count += 1;
                        gathered_chains.append(&mut sub_chains);
                    }
                    Err(e) => {
                        log::debug!("L7Interceptor: failed to poke target {}: {:?}", target, e);
                    }
                }
            }

            // Lock central data and update status
            if let Ok(mut data) = central_data.lock() {
                let own_data = {
                    if let Ok(cfg) = config.lock() {
                        Self::build_own_data(&cfg)
                    } else {
                        StatusChain {
                            id: "fallback".to_string(),
                            terminator: true,
                            last_updated: Self::get_formatted_time(),
                            health: 1,
                            targets: 0,
                            routes: vec![],
                        }
                    }
                };

                // Clear previous and push own first
                data.clear();
                data.push(own_data);
                data.append(&mut gathered_chains);

                // Set local node health
                if targets.is_empty() {
                    data[0].health = 0; // If no targets, it's healthy by default
                } else if connection_pool_count == targets.len() {
                    data[0].health = 0; // Healthy
                } else if connection_pool_count == 0 {
                    data[0].health = 1; // Offline
                } else {
                    data[0].health = 2; // Unhealthy
                }

                // Output human readable status matching l7-snake client formatting
                for chain in data.iter() {
                    let health_str = Self::get_health_human(chain.health);
                    let id = &chain.id;
                    let term = chain.terminator;
                    let up = &chain.last_updated;
                    let tr = chain.targets;
                    let r = chain.routes.join(", ");

                    if term {
                        println!(
                            "TRACE: {} | ID: {} | Term: {} | (-/-) | LastUpdated: {} | Routes: [{}]",
                            health_str, id, term, up, r
                        );
                    } else {
                        println!(
                            "TRACE: {} | ID: {} | Term: {} | ({}/{}) | LastUpdated: {} | Routes: [{}]",
                            health_str, id, term, connection_pool_count, tr, up, r
                        );
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    }

    /// Connects to a target and issues the Poke message
    async fn poke_target(target: &str) -> Result<Vec<StatusChain>, Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = tokio::time::timeout(
            Duration::from_millis(500),
            TcpStream::connect(target),
        ).await??;

        let request = EchoRequest {
            echo: "sss".to_string(),
        };

        let req_bytes = serde_json::to_vec(&request)?;
        stream.write_all(&req_bytes).await?;
        stream.write_all(b"\n").await?;

        let mut buf = vec![0; 65536];
        let bytes_read = stream.read(&mut buf).await?;
        if bytes_read == 0 {
            return Err("Empty response from target".into());
        }

        let chains: Vec<StatusChain> = serde_json::from_slice(&buf[..bytes_read])?;
        Ok(chains)
    }

    /// Server endpoint listener for incoming status trace queries
    async fn run_server_service(
        config: Arc<Mutex<L7SnakeConfig>>,
        central_data: Arc<Mutex<Vec<StatusChain>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let port = {
            if let Ok(cfg) = config.lock() {
                cfg.listen_port
            } else {
                9001
            }
        };

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("L7Interceptor gRPC/TCP server listening on port {}", port);

        loop {
            let (mut stream, _) = listener.accept().await?;
            let data_clone = Arc::clone(&central_data);
            let config_clone = Arc::clone(&config);

            tokio::spawn(async move {
                let mut buf = vec![0; 4096];
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if let Ok(req) = serde_json::from_slice::<EchoRequest>(&buf[..n]) {
                            if req.echo == "sss" {
                                // Update local node's timestamp
                                if let Ok(mut data) = data_clone.lock() {
                                    if !data.is_empty() {
                                        data[0].last_updated = Self::get_formatted_time();

                                        // Apply routing terminator constraints if applicable
                                        if let Ok(cfg) = config_clone.lock() {
                                            if cfg.terminator {
                                                data[0].health = 0;
                                                data[0].targets = 0;
                                                if !data[0].routes.is_empty() {
                                                    data[0].routes[0] = format!("END OF {}", cfg.routes[0]);
                                                }
                                            }
                                        }
                                    }

                                    // Respond with current status lists
                                    if let Ok(resp_bytes) = serde_json::to_vec(&*data) {
                                        let _ = stream.write_all(&resp_bytes).await;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            });
        }
    }
}
