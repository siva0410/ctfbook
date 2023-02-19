	BITS	64
	global 	_start
_start:
	lea rdi, [rel filename]
	xor rsi, rsi
	mov rax, 0x02
	syscall

	test rax, rax
	js end

	push rax
	push rbp
	mov rbp,rsp
	sub rsp, 0x100

	mov rdi, rax
	mov rsi, rsp
	mov rdx, 0x100
	xor rax, rax
	syscall

	mov rdi, 1
	mov rsi, rsp
	mov rdx, 0x100
	mov rax, 0x01
	syscall

	leave
	pop rdi
	mov rax, 0x03
	syscall	
	
end:
	xor rdi, rdi
	mov rax, 0x3c
	syscall

filename:
	db "/etc/lsb-release", 0x00
