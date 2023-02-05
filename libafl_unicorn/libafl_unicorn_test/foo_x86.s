	.file	"foo.c"
	.text
	.section	.text.startup,"ax",@progbits
	.p2align 4
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	endbr64
	movb	$0, -1(%rsp)
	movb	$0, -1(%rsp)
	movzbl	-3(%rsp), %eax
	movzbl	-2(%rsp), %edx
	cmpb	%al, %dl
	jnb	.L3
	movb	$1, -1(%rsp)
	movzbl	-3(%rsp), %eax
	cmpb	$32, %al
	jbe	.L3
	movb	$2, -1(%rsp)
	movzbl	-3(%rsp), %eax
	cmpb	$80, %al
	je	.L6
.L3:
	movzbl	-1(%rsp), %eax
	ret
.L6:
	movb	$3, -1(%rsp)
	movzbl	-2(%rsp), %eax
	cmpb	$36, %al
	jne	.L3
	movb	$4, -1(%rsp)
	jmp	.L3
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 12.2.0-3ubuntu1) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
