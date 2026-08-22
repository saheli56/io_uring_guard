use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use std::time::Duration;
use std::env;
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::thread;

mod events;
mod detector;
mod dashboard;

use events::{Event, RawEvent};
use detector::{Detector, RiskLevel};
use dashboard::{DashboardState, run_dashboard};

mod monitor_skel {
    include!(concat!(env!("OUT_DIR"), "/monitor.skel.rs"));
}
use monitor_skel::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {}

fn handle_event(data: &[u8], detector: &mut Detector, state: &Arc<Mutex<DashboardState>>) -> i32 {
    if data.len() < std::mem::size_of::<RawEvent>() {
        return 0;
    }

    let mut raw = RawEvent::default();
    plain::copy_from_bytes(&mut raw, data).expect("Failed to copy event");

    let mut st = state.lock().unwrap();
    let current_id = st.total_events + 1;
    
    let event = Event::from_raw(&raw, current_id);
    
    if let Some(mut alert) = detector.analyze(&event) {
        if matches!(alert.risk, RiskLevel::High) && st.prevention_mode {
            // ASSASSINATE THE PROCESS!
            unsafe {
                libc::kill(event.pid as i32, libc::SIGKILL);
            }
            alert.blocked = true;
        }
        st.add_alert(alert);
    }
    st.add_event(event);

    0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _args = Args::parse();
    
    if env::var("EUID").unwrap_or_else(|_| "0".to_string()) != "0" && unsafe { libc::geteuid() } != 0 {
        eprintln!("You must run this program as root (sudo)");
        std::process::exit(1);
    }

    let skel_builder = MonitorSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    
    skel.attach()?;

    let detector = Arc::new(Mutex::new(Detector::new()));
    let dash_state = Arc::new(Mutex::new(DashboardState::new()));

    let mut builder = RingBufferBuilder::new();
    
    let detector_clone = Arc::clone(&detector);
    let state_clone = Arc::clone(&dash_state);
    
    builder.add(&skel.maps.events, move |data| {
        let mut det = detector_clone.lock().unwrap();
        handle_event(data, &mut det, &state_clone)
    })?;
    
    let ringbuf = builder.build()?;

    thread::spawn(move || {
        loop {
            if ringbuf.poll(Duration::from_millis(50)).is_err() {
                break;
            }
        }
    });

    run_dashboard(dash_state)?;

    Ok(())
}
