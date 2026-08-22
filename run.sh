#!/bin/bash

# A simple helper script to bypass the Cargo space bug and run the dashboard instantly

echo "Compiling IORing Guard..."

# 1. Copy the latest source code to the safe /tmp directory
cp -r "/home/masum/Repositories (Linux)/io_uring guard/src/"* /tmp/ioring_guard_copy/src/ 2>/dev/null
cp -r "/home/masum/Repositories (Linux)/io_uring guard/ebpf/"* /tmp/ioring_guard_copy/ebpf/ 2>/dev/null

# 2. Build the project
cd /tmp/ioring_guard_copy
cargo build

if [ $? -eq 0 ]; then
    # 3. Copy the binary back and run it as root
    cp target/debug/ioring_guard "/home/masum/Repositories (Linux)/io_uring guard/ioring_guard_bin"
    
    cd "/home/masum/Repositories (Linux)/io_uring guard"
    echo "Starting Dashboard..."
    sudo ./ioring_guard_bin
else
    echo "Compilation failed! Please check the errors above."
fi
