import json
import os
import sys

try:
    from huggingface_hub import hf_hub_download
    from llama_cpp import Llama
except ImportError:
    print("[-] Error: Missing required libraries.")
    print("Please run: pip install llama-cpp-python huggingface-hub")
    sys.exit(1)

def download_model():
    print("[*] Checking for local Micro-LLM (Qwen 2.5 0.5B)...")
    repo_id = "Qwen/Qwen2.5-0.5B-Instruct-GGUF"
    filename = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
    
    # This caches the model so it only downloads once (~350MB)
    model_path = hf_hub_download(repo_id=repo_id, filename=filename)
    print(f"[+] Model ready at: {model_path}")
    return model_path

def parse_exploit(description):
    model_path = download_model()
    
    print("[*] Loading Model into memory (CPU)...")
    # Silence the C++ output for a cleaner terminal presentation
    import logging
    logging.getLogger("llama_cpp").setLevel(logging.ERROR)
    
    llm = Llama(
        model_path=model_path,
        n_ctx=1024,      # Context window
        n_threads=4,     # Number of CPU threads to use
        verbose=False    # Hide C++ initialization logs
    )

    # Qwen-specific prompt format
    prompt = f"""<|im_start|>system
You are a cybersecurity expert building io_uring signatures. Extract the system calls (opcodes) and target files from the user's exploit description. 
Return ONLY a raw JSON object, no markdown blocks, no code blocks, no other text.
Format: {{"target_opcodes": ["OPCODE_NAME"], "target_files": ["file_path"]}}
Valid io_uring opcodes: READV, WRITEV, OPENAT, CONNECT, SPLICE, TIMEOUT, etc.<|im_end|>
<|im_start|>user
Exploit Description: {description}<|im_end|>
<|im_start|>assistant
"""
    
    print(f"\n[*] Analyzing Exploit Description:\n    \"{description}\"")
    print("[*] Running local offline AI inference...")
    
    response = llm(
        prompt,
        max_tokens=100,
        stop=["<|im_end|>"],
        temperature=0.1
    )
    
    output = response["choices"][0]["text"].strip()
    
    try:
        # Clean up any potential markdown formatting the LLM might have added
        if output.startswith("```json"):
            output = output[7:]
        if output.endswith("```"):
            output = output[:-3]
            
        parsed = json.loads(output.strip())
        print("\n[+] AI Analysis Complete! Generated Signature:")
        print(json.dumps(parsed, indent=2))
        return parsed
    except json.JSONDecodeError:
        print("\n[-] Error: LLM did not return perfect JSON. (Try running again)")
        print(f"Raw output: {output}")
        return None

if __name__ == "__main__":
    # Sample Exploit-DB description (DirtyPipe variant)
    sample_exploit = "This critical vulnerability allows a local unprivileged attacker to overwrite read-only files such as /etc/passwd by abusing the splice system call inside io_uring to gain root."
    
    print("=== IORing Guard: Local Offline AI Signature Generator ===")
    parse_exploit(sample_exploit)
