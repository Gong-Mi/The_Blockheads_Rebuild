
/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so:     file format elf32-littlearm


Disassembly of section .text:

00940f24 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x28ea0>:
  940f24:	e92d4010 	push	{r4, lr}
  940f28:	e24dd00c 	sub	sp, sp, #12
  940f2c:	e59f3058 	ldr	r3, [pc, #88]	@ 940f8c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x28f08>
  940f30:	e08f3003 	add	r3, pc, r3
  940f34:	ee002a10 	vmov	s0, r2
  940f38:	e3002000 	movw	r2, #0
  940f3c:	e59fc040 	ldr	ip, [pc, #64]	@ 940f84 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x28f00>
  940f40:	e79cc003 	ldr	ip, [ip, r3]
  940f44:	e300e001 	movw	lr, #1
  940f48:	e59f4038 	ldr	r4, [pc, #56]	@ 940f88 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x28f04>
  940f4c:	e7943003 	ldr	r3, [r4, r3]
  940f50:	e58d0008 	str	r0, [sp, #8]
  940f54:	e58d1004 	str	r1, [sp, #4]
  940f58:	ed8d0a00 	vstr	s0, [sp]
  940f5c:	e59d0008 	ldr	r0, [sp, #8]
  940f60:	e5931000 	ldr	r1, [r3]
  940f64:	e0800001 	add	r0, r0, r1
  940f68:	e5c0e000 	strb	lr, [r0]
  940f6c:	e59d0008 	ldr	r0, [sp, #8]
  940f70:	e59c1000 	ldr	r1, [ip]
  940f74:	e0800001 	add	r0, r0, r1
  940f78:	e5c02000 	strb	r2, [r0]
  940f7c:	e28dd00c 	add	sp, sp, #12
  940f80:	e8bd8010 	pop	{r4, pc}
  940f84:	ffffe6bc 			@ <UNDEFINED> instruction: 0xffffe6bc
  940f88:	ffffe6b8 			@ <UNDEFINED> instruction: 0xffffe6b8
  940f8c:	0071ebbc 	ldrhteq	lr, [r1], #-188	@ 0xffffff44
