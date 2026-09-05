
/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so:     file format elf32-littlearm


Disassembly of section .text:

00940f90 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x28f0c>:
  940f90:	e24dd00c 	sub	sp, sp, #12
  940f94:	e59f2050 	ldr	r2, [pc, #80]	@ 940fec <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x28f68>
  940f98:	e08f2002 	add	r2, pc, r2
  940f9c:	e3003003 	movw	r3, #3
  940fa0:	eeb00b08 	vmov.f64	d0, #8	@ 0x40400000  3.0
  940fa4:	e59fc03c 	ldr	ip, [pc, #60]	@ 940fe8 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x28f64>
  940fa8:	e79c2002 	ldr	r2, [ip, r2]
  940fac:	e58d0008 	str	r0, [sp, #8]
  940fb0:	e58d1004 	str	r1, [sp, #4]
  940fb4:	e59d0008 	ldr	r0, [sp, #8]
  940fb8:	e5921000 	ldr	r1, [r2]
  940fbc:	e0800001 	add	r0, r0, r1
  940fc0:	ed901b00 	vldr	d1, [r0]
  940fc4:	eeb41bc0 	vcmpe.f64	d1, d0
  940fc8:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  940fcc:	e3000000 	movw	r0, #0
  940fd0:	c3a00001 	movgt	r0, #1
  940fd4:	e2000001 	and	r0, r0, #1
  940fd8:	e6af0070 	sxtb	r0, r0
  940fdc:	e58d3000 	str	r3, [sp]
  940fe0:	e28dd00c 	add	sp, sp, #12
  940fe4:	e12fff1e 	bx	lr
  940fe8:	ffffe62c 			@ <UNDEFINED> instruction: 0xffffe62c
  940fec:	0071eb54 	rsbseq	lr, r1, r4, asr fp
