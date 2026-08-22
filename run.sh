#!/bin/bash
echo "Building directly in Innofusion folder (since there are no spaces in the path!)..."
cargo build --release
if [ $? -eq 0 ]; then
    echo "Starting Dashboard..."
    sudo ./target/release/ioring_guard
else
    echo "Compilation failed! Please check the errors above."
fi
