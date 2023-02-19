	BITS	64
	global_start
_start:
	xor rax, rax
	mov al, 1
	xor rcx, rcx
	mov cl, 9
	inc cl
loop:
	add rax, rax
	dec rcx
	jnz loop
end:
	jmp end
