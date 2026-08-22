use crate::events::Event;
use serde::Deserialize;
use std::fs;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct ExploitSignature {
    pub cve: String,
    pub edb_id: String,
    pub name: String,
    pub description: String,
    pub target_opcodes: Vec<String>,
    pub target_files: Vec<String>,
    pub risk: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub event: Event,
    pub risk: RiskLevel,
    pub reason: String,
    pub blocked: bool,
}

pub struct Detector {
    signatures: Vec<ExploitSignature>,
    pid_tracker: HashMap<u32, (u64, usize)>, // PID -> (last_timestamp, count)
}

impl Detector {
    pub fn new() -> Self {
        let signatures = match fs::read_to_string("exploitdb_signatures.json") {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| {
                eprintln!("Failed to parse exploitdb_signatures.json");
                Vec::new()
            }),
            Err(_) => {
                eprintln!("Could not load exploitdb_signatures.json");
                Vec::new()
            }
        };
        Self { 
            signatures,
            pid_tracker: HashMap::new(),
        }
    }

    pub fn analyze(&mut self, event: &Event) -> Option<Alert> {
        // Enterprise Whitelist: Ignore DoS checks for known high-IO applications
        let trusted_binaries = ["fio", "nginx", "postgres", "mysql"];
        let is_trusted = trusted_binaries.contains(&event.comm.as_str());

        // DoS Tracker logic
        if !is_trusted {
            let (last_ts, count) = self.pid_tracker.entry(event.pid).or_insert((event.timestamp, 0));
            if event.timestamp - *last_ts > 1_000_000_000 { // 1 second in ns
                *last_ts = event.timestamp;
                *count = 0;
            }
            *count += 1;

            if *count > 200 { // 200 io_uring requests per second is highly suspicious for a normal app
                return Some(Alert {
                    event: event.clone(),
                    risk: RiskLevel::Critical,
                    reason: format!("io_uring Denial of Service (DoS) Flood Detected (>200 ops/sec)"),
                    blocked: false,
                });
            }
        }
        for sig in &self.signatures {
            if sig.target_opcodes.contains(&event.opcode_name.to_string()) {
                if sig.target_files.is_empty() || sig.target_files.iter().any(|f| event.filename.ends_with(f)) {
                    let risk = match sig.risk.as_str() {
                        "High" => RiskLevel::High,
                        "Medium" => RiskLevel::Medium,
                        _ => RiskLevel::Low,
                    };
                    let reason_prefix = if sig.edb_id == "N/A" {
                        "[Threat Intel]".to_string()
                    } else {
                        format!("[EDB-{}]", sig.edb_id)
                    };
                    return Some(Alert {
                        event: event.clone(),
                        risk,
                        reason: format!("{} {}", reason_prefix, sig.name),
                        blocked: false,
                    });
                }
            }
        }

        match event.opcode_name {
            "CONNECT" | "ACCEPT" | "SEND" | "RECV" => {
                return Some(Alert {
                    event: event.clone(),
                    risk: RiskLevel::Medium,
                    reason: format!("Network I/O via io_uring ({})", event.opcode_name),
                    blocked: false,
                });
            }
            "OPENAT" | "OPENAT2" => {
                if !event.filename.is_empty() {
                    return Some(Alert {
                        event: event.clone(),
                        risk: RiskLevel::Low,
                        reason: format!("File opened via io_uring: {}", event.filename),
                        blocked: false,
                    });
                }
            }
            _ => {}
        }

        None
    }
}
