use crate::events::Event;

#[derive(Debug, Clone)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub event: Event,
    pub risk: RiskLevel,
    pub reason: String,
    pub blocked: bool,
}

pub struct Detector {}

impl Detector {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze(&mut self, event: &Event) -> Option<Alert> {
        if event.opcode_name == "READV" || event.opcode_name == "READ" || event.opcode_name == "OPENAT" || event.opcode_name == "OPENAT2" {
            let sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/hostname", "authorized_keys", "id_rsa"];
            
            for sensitive in sensitive_files.iter() {
                if event.filename.ends_with(sensitive) {
                    return Some(Alert {
                        event: event.clone(),
                        risk: RiskLevel::High,
                        reason: format!("io_uring {} access to sensitive file: {}", event.opcode_name, event.filename),
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
