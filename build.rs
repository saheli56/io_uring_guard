use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let bpf_src = "ebpf/monitor.bpf.c";
    
    SkeletonBuilder::new()
        .source(bpf_src)
        .clang_args(["-I."]) // So it finds vmlinux.h in the root directory
        .build_and_generate(&out.join("monitor.skel.rs"))
        .expect("bpf skeleton generation failed");
        
    println!("cargo:rerun-if-changed={}", bpf_src);
    println!("cargo:rerun-if-changed=vmlinux.h");
}
