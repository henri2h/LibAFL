	.arch armv7-a
	.fpu vfpv3-d16
	.eabi_attribute 28, 1
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 2
	.eabi_attribute 34, 1
	.eabi_attribute 18, 4
	.file	"foo.c"
	.text
	.section	.text.startup,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	main
	.syntax unified
	.thumb
	.thumb_func
	.type	main, %function
main:
	@ args = 0, pretend = 0, frame = 8
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	sub	sp, sp, #8
	movs	r2, #0
	movs	r3, #1
	strb	r2, [sp, #7]
	strb	r3, [sp, #7]
	ldrb	r2, [sp, #5]	@ zero_extendqisi2
	ldrb	r3, [sp, #6]	@ zero_extendqisi2
	cmp	r2, r3
	bls	.L3
	movs	r3, #2
	strb	r3, [sp, #7]
	ldrb	r3, [sp, #5]	@ zero_extendqisi2
	cmp	r3, #32
	bls	.L3
	movs	r3, #3
	strb	r3, [sp, #7]
	ldrb	r3, [sp, #5]	@ zero_extendqisi2
	cmp	r3, #80
	beq	.L7
.L3:
	ldrb	r0, [sp, #7]	@ zero_extendqisi2
	add	sp, sp, #8
	@ sp needed
	bx	lr
.L7:
	movs	r3, #4
	strb	r3, [sp, #7]
	ldrb	r3, [sp, #6]	@ zero_extendqisi2
	cmp	r3, #36
	itt	eq
	moveq	r3, #5
	strbeq	r3, [sp, #7]
	b	.L3
	.size	main, .-main
	.ident	"GCC: (Ubuntu 12.2.0-3ubuntu1) 12.2.0"
	.section	.note.GNU-stack,"",%progbits