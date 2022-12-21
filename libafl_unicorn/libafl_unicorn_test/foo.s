	.arch armv8-a
	.file	"foo.c"
	.text
	.section	.text.startup,"ax",@progbits
	.align	2
	.p2align 4,,11
	.global	main
	.type	main, %function
main:
.LFB0:
	.cfi_startproc
	sub	sp, sp, #16
	.cfi_def_cfa_offset 16
	ldrb	w1, [sp, 13]
	ldrb	w0, [sp, 14]
	and	w0, w0, 255
	cmp	w0, w1, uxtb
	bcs	.L3
	mov	w0, 1
	strb	w0, [sp, 15]
	ldrb	w0, [sp, 13]
	and	w0, w0, 255
	cmp	w0, 32
	bls	.L3
	mov	w0, 2
	strb	w0, [sp, 15]
	ldrb	w0, [sp, 13]
	and	w0, w0, 255
	cmp	w0, 80
	beq	.L7
.L3:
	ldrb	w0, [sp, 15]
	add	sp, sp, 16
	.cfi_remember_state
	.cfi_def_cfa_offset 0
	and	w0, w0, 255
	ret
.L7:
	.cfi_restore_state
	mov	w0, 3
	strb	w0, [sp, 15]
	ldrb	w0, [sp, 14]
	and	w0, w0, 255
	cmp	w0, 36
	bne	.L3
	mov	w0, 4
	strb	w0, [sp, 15]
	b	.L3
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 12.2.0-3ubuntu1) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
