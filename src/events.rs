use plain::Plain;
use std::fs;

#[repr(C)]
#[derive(Default, Debug)]
pub struct RawEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub opcode: u8,
    pub _pad1: [u8; 3], 
    pub fd: i32,
    pub filename: [u8; 32],
}

unsafe impl Plain for RawEvent {}

#[derive(Debug, Clone)]
pub struct Event {
    pub id: usize, // NEW: Unique Serial Number for the UI
    pub timestamp: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub comm: String,
    pub opcode: u8,
    pub opcode_name: &'static str,
    pub fd: i32,
    pub filename: String,
}

impl Event {
    pub fn from_raw(raw: &RawEvent, current_id: usize) -> Self {
        let comm = String::from_utf8_lossy(&raw.comm)
            .trim_end_matches('\0')
            .to_string();

        let resolved_path = if raw.fd >= 0 {
            match fs::read_link(format!("/proc/{}/fd/{}", raw.pid, raw.fd)) {
                Ok(path) => path.to_string_lossy().to_string(),
                Err(_) => format!("fd:{}", raw.fd),
            }
        } else {
            String::new()
        };

        Self {
            id: current_id,
            timestamp: raw.timestamp,
            pid: raw.pid,
            tgid: raw.tgid,
            uid: raw.uid,
            comm,
            opcode: raw.opcode,
            opcode_name: get_opcode_name(raw.opcode),
            fd: raw.fd,
            filename: resolved_path,
        }
    }
}

pub fn get_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0 => "NOP",
        1 => "READV",
        2 => "WRITEV",
        3 => "FSYNC",
        4 => "READ_FIXED",
        5 => "WRITE_FIXED",
        6 => "POLL_ADD",
        7 => "POLL_REMOVE",
        8 => "SYNC_FILE_RANGE",
        9 => "SENDMSG",
        10 => "RECVMSG",
        11 => "TIMEOUT",
        12 => "TIMEOUT_REMOVE",
        13 => "ACCEPT",
        14 => "ASYNC_CANCEL",
        15 => "LINK_TIMEOUT",
        16 => "CONNECT",
        17 => "FALLOCATE",
        18 => "OPENAT",
        19 => "CLOSE",
        20 => "FILES_UPDATE",
        21 => "STATX",
        22 => "READ",
        23 => "WRITE",
        24 => "FADVISE",
        25 => "MADVISE",
        26 => "SEND",
        27 => "RECV",
        28 => "OPENAT2",
        29 => "EPOLL_CTL",
        _ => "UNKNOWN",
    }
}
